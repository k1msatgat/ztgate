#!/usr/bin/node
/* ztgate-deploy — ztgate 서버를 git 원격의 ref 에서 패키지로 빌드해 깔고, 새 서버를 검사하고, 떨어지면 이전
 * 패키지로 스스로 되돌린다. MCP 의 deploy, deploy_rollback, deploy_status 가 sudo 로 부른다.
 *
 *   sudo -n ztgate-deploy           stdin 에 JSON 한 덩어리: {"cmd":"deploy","ref":"main"} (deploy | deploy_rollback |
 *                                   deploy_status). sudoers 는 인자 없이 부르는 것만 연다
 *   ztgate-deploy run <job>         작업 하나. start() 가 systemd-run 으로 띄운 ztgate-deploy.service 안에서만 돈다
 *   ztgate-deploy build <ref>       root 셸에서. 빌드해 보관만 하고 깔지 않는다 (packaging/migrate-to-package.sh)
 *
 * mcp/install.sh 가 /opt/ztgate-mcp/libexec/ztgate-deploy 로 놓는다. 배포되는 패키지 밖에 있으므로, 배포 기능이
 * 없는 옛 ref 로 내려가도 이 프로그램과 되돌리기는 남는다.
 *
 * 신뢰의 뿌리는 /etc/ztgate-deploy/deploy.conf (root, 남이 쓸 수 없음) 의 REPO 와 BRANCHES / TAGS 다. 요청에 실리는
 * 것은 ref 와 감수할 위험뿐이다. 가져오기는 deploy.conf 에서 만든 refspec 으로만 하고 SHA 로는 가져오지 않는다
 * (포크의 커밋을 막는다). 커밋은 허용된 ref 에서 닿아야 한다. 빌드는 ztgate-build 계정의 묶인 유닛이 git archive 의
 * tar 만 받아서 한다. 이것은 보안 경계가 아니다 — 그 소스의 패키지는 어차피 root 로 %post 를 돈다. 정직한 소스의
 * 버그가 장비와 VPN 을 다치게 하지 못하게 하는 손해 제한이다 (docs/decisions/0014-deploy-from-remote.md).
 *
 * 지금 설치된 것은 적어 두지 않고 매번 패키지 DB 에서 읽는다. 적는 것은 추가만 하는 사실이다: 작업마다
 * jobs/<id>/request.json (한 번), events.jsonl (그 작업의 실행기만 덧붙인다), 보관 패키지의 메타, history.jsonl.
 *
 * root 로 도는 코드라 npm 패키지를 쓰지 않는다. 호출한 쪽의 검증은 믿지 않고 여기서 다시 한다. */
'use strict';

const DEFAULT_REPO = 'https://github.com/k1msatgat/ztgate.git';

class DeployError extends Error {}

function fail(msg) {
	throw new DeployError(msg);
}

/* ---- 순수 ------------------------------------------------------------------- */

const PATTERN = /^[A-Za-z0-9._/-]*\*?[A-Za-z0-9._/-]*$/;

/* deploy.conf 의 KEY=VALUE. 셸로 읽지 않는다. 모르는 키와 틀린 값은 거절한다. REPO 는 https:// 이거나, 시험용으로
 * 이 장비의 절대 경로 (file:// 또는 /) 다. */
function parseConf(text) {
	const conf = { repo: DEFAULT_REPO, branches: ['*'], tags: ['v*'], keep: 5 };

	text.split('\n').forEach((raw, i) => {
		const line = raw.trim();
		const where = `deploy.conf line ${i + 1}`;

		if (line === '' || line.startsWith('#')) {
			return;
		}
		const m = /^([A-Z_]+)=(.*)$/.exec(line);
		if (!m) {
			fail(`${where}: expected KEY=VALUE`);
		}
		const v = m[2].trim();

		if (m[1] === 'REPO') {
			if (!/^(https:\/\/[A-Za-z0-9.-]+(:\d+)?\/[A-Za-z0-9._~/-]+|(file:\/\/)?\/[A-Za-z0-9._/-]+)$/.test(v)) {
				fail(`${where}: REPO must be an https:// URL or an absolute path on this host`);
			}
			conf.repo = v;
		} else if (m[1] === 'BRANCHES' || m[1] === 'TAGS') {
			const list = v === '' ? [] : v.split(/\s+/);
			for (const p of list) {
				if (!PATTERN.test(p) || p.includes('..') || p.startsWith('-')) {
					fail(`${where}: '${p}' is not a ref name or a pattern with one *`);
				}
			}
			conf[m[1].toLowerCase()] = list;
		} else if (m[1] === 'KEEP') {
			if (!/^\d{1,2}$/.test(v) || Number(v) < 1 || Number(v) > 50) {
				fail(`${where}: KEEP must be 1..50`);
			}
			conf.keep = Number(v);
		} else {
			fail(`${where}: unknown key ${m[1]} (REPO, BRANCHES, TAGS, KEEP)`);
		}
	});

	return conf;
}

/* 호출한 쪽의 ref (경계). 7-40 hex 는 커밋, 그 밖은 브랜치나 태그의 이름이다. */
function wantRef(v) {
	if (typeof v !== 'string') {
		fail('ref must be a string');
	}
	if (/^[0-9a-fA-F]{7,40}$/.test(v)) {
		return { kind: 'commit', prefix: v.toLowerCase() };
	}
	if (!/^[A-Za-z0-9._/-]{1,100}$/.test(v) || /^[-/.]|\.\.|\/\/|\/\.|[/.]$|\.lock$/.test(v)) {
		fail(`ref '${v}' is neither a branch or tag name nor a 7-40 hex commit`);
	}

	return { kind: 'name', name: v };
}

/* git 의 refspec 처럼 * 는 / 를 넘어 아무 글자나 받는다. */
function globMatch(pattern, name) {
	const re = pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');

	return new RegExp(`^${re}$`).test(name);
}

/* 이름이 허용된 브랜치나 태그인가. 커밋은 여기서는 늘 true 이고, 허용된 ref 에서 닿는지는 가져온 뒤에 본다. */
function refAllowed(conf, input) {
	return input.kind === 'commit' ||
		conf.branches.some((p) => globMatch(p, input.name)) || conf.tags.some((p) => globMatch(p, input.name));
}

/* 저장소의 ref 가 지금의 허용 목록에 드는가. 예전에 허용했다가 뺀 ref 는 저장소에 남아 있을 수 있다. */
function refnameAllowed(conf, refname) {
	if (refname.startsWith('refs/remotes/origin/')) {
		return conf.branches.some((p) => globMatch(p, refname.slice('refs/remotes/origin/'.length)));
	}
	if (refname.startsWith('refs/tags/')) {
		return conf.tags.some((p) => globMatch(p, refname.slice('refs/tags/'.length)));
	}

	return false;
}

function refspecs(conf) {
	return [
		...conf.branches.map((p) => `+refs/heads/${p}:refs/remotes/origin/${p}`),
		...conf.tags.map((p) => `+refs/tags/${p}:refs/tags/${p}`),
	];
}

/* proto.h 의 텍스트에서. MIN 이 없는 옛 ref 는 MIN = MAX 로 본다. 실행하지 않고 읽기만 한다. */
function parseProtocol(text) {
	const max = /^#define PROTOCOL_VERSION (\d+)/m.exec(text);
	const min = /^#define PROTOCOL_VERSION_MIN (\d+)/m.exec(text);

	if (!max) {
		return null;
	}

	return { min: Number(min ? min[1] : max[1]), max: Number(max[1]) };
}

/* 새 서버가 지금 서버가 받는 버전을 하나도 받지 않으면, 지금 붙은 클라이언트는 모두 끊긴다 (ADR 0012).
 * 지금 붙은 클라이언트는 지금 서버의 범위 안에 있다. */
function protocolRisk(from, to) {
	if (!from || !to) {
		return null;
	}

	return from.min <= to.max && to.min <= from.max ? null : 'protocol_break';
}

/* 커밋 시각(UTC)과 id 로 packaging/build.sh 의 SNAPSHOT. 같은 커밋은 늘 같은 값이다. */
function snapshotOf(unixSec, commit) {
	return `${new Date(unixSec * 1000).toISOString().slice(0, 19).replace(/[-:T]/g, '')}.g${commit.slice(0, 12)}`;
}

/* 패키지 DB 가 말하는 판. packaging/build.sh 와 같은 규칙이고, 빌드한 파일에서 읽은 값과 맞춰 본다. */
function versionOf(kind, version, snapshot) {
	return kind === 'rpm' ? `${version}-0.${snapshot}` : `${version}~${snapshot}`;
}

/* 작업의 단계와, 단계마다 받는 사건과 그 뒤의 단계. 표에 없는 사건은 실행기의 버그다 (emit 이 던진다).
 * 단계는 따로 적지 않고 사건을 이 표로 접어 끌어낸다. */
const NEXT = {
	queued: { started: (req) => (req.kind === 'rollback' ? 'backing_up' : 'fetching') },
	fetching: { resolved: 'fetching', building: 'building', reused: 'backing_up', finished: 'done' },
	building: { built: 'backing_up', finished: 'done' },
	backing_up: { backed_up: 'installing', finished: 'done' },
	installing: { installed: 'checking', reverting: 'reverting', finished: 'done' },
	checking: { checked: 'checking', reverting: 'reverting', finished: 'done' },
	reverting: { installed: 'checking', finished: 'done' },
	done: {},
};

/* 끝난 작업의 결과. 이름이 "장비가 바뀌었나"를 먼저 말한다.
 *   installed    대상이 깔렸고 검사를 통과했다
 *   unchanged    대상이 이미 깔려 있었다. 아무것도 하지 않았다
 *   built        (build 작업) 빌드해 보관했다. 깔지 않았다
 *   failed       깔기 전에 멈췄거나 rpm / dpkg 가 거절했다. 장비는 그대로다
 *   reverted     대상이 검사에 떨어져 출발점을 다시 깔았고, 그것은 검사를 통과했다
 *   broken       되돌리기도 떨어졌거나 되돌릴 패키지가 없었다. 사람이 봐야 한다
 *   interrupted  실행기가 끝을 적지 못하고 사라졌다 (재부팅, kill). 스스로 되돌리지 않는다 */
const OUTCOMES = ['installed', 'unchanged', 'built', 'failed', 'reverted', 'broken', 'interrupted'];

function secs(from, to) {
	return Math.max(0, Math.round((Date.parse(to) - Date.parse(from)) / 1000));
}

function initialView(req) {
	return {
		id: req.id, kind: req.kind, phase: 'queued', outcome: null, target: { ...req.target }, from: null,
		was_running: null, accept: req.accept, actor: req.actor, requested_at: req.requested_at, ended_at: null,
		phases: [], since: req.requested_at, build: null, backup: null, check: null, revert_check: null,
		reverting: false, error: null, note: null,
	};
}

/* 사건 하나를 접는다. 표에 없는 넘어감이면 던진다. */
function step(v, req, e) {
	const to = NEXT[v.phase][e.ev];

	if (to === undefined) {
		fail(`job ${req.id}: event '${e.ev}' cannot follow phase '${v.phase}'`);
	}

	const n = { ...v, phase: typeof to === 'function' ? to(req) : to };
	if (n.phase !== v.phase) {
		n.phases = [...v.phases, { phase: v.phase, sec: secs(v.since, e.t) }];
		n.since = e.t;
	}

	if (e.ev === 'started') {
		n.from = e.from;
		n.was_running = e.was_running;
	} else if (e.ev === 'resolved') {
		n.target = { ...n.target, commit: e.commit, version: e.version, protocol: e.protocol };
	} else if (e.ev === 'built') {
		n.build = { sec: e.sec, memory_peak: e.memory_peak };
	} else if (e.ev === 'backed_up') {
		n.backup = e.file;
	} else if (e.ev === 'checked') {
		n[v.reverting ? 'revert_check' : 'check'] = e.check;
	} else if (e.ev === 'reverting') {
		n.reverting = true;
	} else if (e.ev === 'finished') {
		n.outcome = e.outcome;
		n.error = e.error || null;
		n.note = e.note || null;
		n.ended_at = e.t;
	}

	return n;
}

/* 작업의 모습. unit 은 지금의 ztgate-deploy.service 다 ({ active, job }). 끝이 적히지 않았는데 이 작업의 유닛이
 * 돌고 있지 않으면 interrupted 다 — 읽을 때 정하고 고쳐 쓰지 않는다. */
function reduceJob(req, events, unit, now) {
	let v = initialView(req);

	for (const e of events) {
		try {
			v = step(v, req, e);
		} catch (err) {
			v = { ...v, error: err.message };
			break;
		}
	}
	if (v.outcome === null && !(unit.active && unit.job === req.id)) {
		v = { ...v, outcome: 'interrupted' };
	}

	const { since, reverting, ...out } = v;

	return { ...out, elapsed_sec: secs(req.requested_at, v.ended_at || now) };
}

/* 지금 것 바로 앞에 깔려 있던 것. history 의 줄은 검사를 통과한 설치마다 하나 ({ package, from }) 이므로,
 * 지금 것을 깐 가장 최근 줄의 from 이다. 되돌려진 시도는 줄을 남기지 않아 "이전" 이 되지 않는다. */
function previousOf(history, commit) {
	for (let i = history.length - 1; i >= 0; i--) {
		if (history[i].package === commit) {
			return history[i].from || null;
		}
	}

	return null;
}

/* 지울 보관 패키지. 최근에 지었거나 깔린 순서로 keep 개를 남기고, protect (지금 것, 이전 것) 는 늘 남긴다. */
function pruneList(kept, history, protect, keep) {
	const used = new Map(history.map((h) => [h.package, Date.parse(h.t)]));
	const recent = (k) => Math.max(Date.parse(k.built_at), used.get(k.commit) || 0);

	return [...kept].sort((a, b) => recent(b) - recent(a)).slice(keep)
		.map((k) => k.commit).filter((c) => !protect.includes(c));
}

/* 설치 뒤 ztgate.service 를 1초마다 본 값으로 판정한다. 'wait' 이면 더 본다. 재시작이 하나라도 늘었으면
 * 떨어진다 — Restart=on-failure 가 되살린 서버는 active 로 보여도 죽었다 산 것이다. */
function settle(samples, installedAt, settleSec, deadlineSec) {
	const first = samples[0];
	const last = samples[samples.length - 1];

	if (last.restarts > first.restarts) {
		return { state: 'fail', detail: `restarted ${last.restarts - first.restarts} time(s) after the install (exit status ${last.exit_status})` };
	}
	if (last.state === 'failed' || last.state === 'inactive') {
		return { state: 'fail', detail: `${last.state} (${last.result}, exit status ${last.exit_status})` };
	}
	if (last.state === 'active' && last.started_at < installedAt) {
		return { state: 'fail', detail: 'the server still runs the process from before the install' };
	}

	let i = samples.length - 1;
	while (i > 0 && samples[i - 1].state === 'active' && samples[i - 1].pid === last.pid) {
		i--;
	}
	const steady = last.state === 'active' ? (last.t - samples[i].t) / 1000 : 0;

	if (steady >= settleSec) {
		return { state: 'pass', detail: `active, same pid ${last.pid} for ${Math.round(steady)}s, no restarts` };
	}
	if ((last.t - first.t) / 1000 >= deadlineSec) {
		return { state: 'fail', detail: `not steady within ${deadlineSec}s (${last.state}/${last.sub})` };
	}

	return { state: 'wait' };
}

module.exports = {
	parseConf, wantRef, globMatch, refAllowed, refnameAllowed, refspecs, parseProtocol, protocolRisk, snapshotOf,
	versionOf, NEXT, OUTCOMES, step, initialView, reduceJob, previousOf, pruneList, settle, DeployError,
};
