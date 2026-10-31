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

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const dgram = require('node:dgram');
const { spawnSync } = require('node:child_process');

const ETC = '/etc/ztgate-deploy';
const CONF_FILE = `${ETC}/deploy.conf`;
const SIGNERS_FILE = `${ETC}/allowed_signers`;
const STATE = '/var/lib/ztgate-deploy';
const REPO_DIR = `${STATE}/src.git`;
const PACKAGES = `${STATE}/packages`;
const JOBS = `${STATE}/jobs`;
const BUILDS = `${STATE}/build`;
const HISTORY = `${STATE}/history.jsonl`;
const WINDOW = '/run/ztgate-deploy/window';	/* mcp/ctl.cjs 가 읽는다 */

/* 작업 유닛의 이름은 하나다. systemd 는 같은 이름의 유닛을 둘 만들지 않으므로 이것이 곧 "한 번에 하나"다.
 * 잠금 파일이 없으니 죽은 작업이 남기는 잠금도 없다. */
const UNIT = 'ztgate-deploy.service';
const BUILD_USER = 'ztgate-build';

const SERVER_UNIT = 'ztgate.service';
const SERVER_BIN = '/opt/ztgate/server/bin/vpn_server';
const CTL = '/usr/sbin/ztgate_ctl';
const BACKUP = '/usr/sbin/ztgate-backup';
const SERVER_ETC = '/etc/ztgate';
const SERVER_KEY = `${SERVER_ETC}/server.key`;
const SERVER_ENV = `${SERVER_ETC}/server.env`;
const SYNC_MARK = `${SERVER_ETC}/.sync-primary`;
const STATUS_SOCK = '/run/ztgate/status.sock';
const AUDIT_FILE = '/var/log/ztgate/audit.log';

const DEFAULT_REPO = 'https://github.com/k1msatgat/ztgate.git';
const SETTLE_SEC = 15;
const START_DEADLINE_SEC = 60;
const WAIT_MAX_SEC = 150;
const JOB_KEEP = 20;
const LOG_TAIL = 15;
const JOB_ID = /^d-\d{8}T\d{6}Z-[0-9a-f]{4}$/;
const RISKS = ['protocol_break', 'no_revert'];
const REQUESTS = ['deploy', 'deploy_rollback', 'deploy_status'];	/* stdin 으로 받는 명령. mcp/server.js 의 도구와 같은 이름 */
const MSG_TYPE_VERSION = 11;	/* lib/common/include/proto.h. ADR 0012: 이 답의 모양은 바뀌지 않는다 */

const ENV = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };

/* 빌드 유닛이 돌린다. 바뀌는 입력은 KIND 와 SNAPSHOT 두 환경 변수이고 둘 다 root 가 정한다. 마지막 줄은 이 유닛의
 * 메모리 최고치다 (MemoryMax 에 얼마나 붙었는지 사건에 남긴다. 커널 5.19 앞에는 없는 파일이라 비어 있을 수 있다). */
const BUILD_SCRIPT = [
	'mkdir src',
	'tar -xf src.tar -C src',
	'cd src',
	'make server',
	'server/bin/vpn_server selftest',
	'packaging/build.sh "$KIND" ../out',
	'echo "memory_peak=$(cat "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.peak" 2> /dev/null)"',
].join('\n');

/* systemd-run 의 일회용 유닛 둘. 가져오기는 root 이지만 능력 없이 저장소만 쓰고, 빌드는 네트워크 없이 빌드 폴더만
 * 쓴다. BindsTo 로 작업 유닛에 묶어 작업이 죽으면 같이 멈춘다. CPUWeight 와 Nice 는 1 CPU 장비에서 VPN 의 데이터
 * 경로가 CPU 를 먼저 받게 한다. MemorySwapMax=0 이 없으면 MemoryMax 를 넘는 몫은 스왑으로 가서 빌드가 장비를
 * 느리게 만들며 끝까지 돈다. 넘으면 빌드만 죽는다 (failed, 장비 그대로). */
const SANDBOX = {
	fetch: () => ['-p', 'ProtectSystem=strict', '-p', `ReadWritePaths=${REPO_DIR}`, '-p', 'ProtectHome=yes',
		'-p', 'PrivateTmp=yes', '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=', '-p', 'RuntimeMaxSec=600'],
	build: (dir) => ['--uid', BUILD_USER, '--gid', BUILD_USER, '-p', `WorkingDirectory=${dir}`, '-p', `ReadWritePaths=${dir}`,
		'-p', 'PrivateNetwork=yes', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=yes', '-p', 'PrivateTmp=yes',
		'-p', 'NoNewPrivileges=yes', '-p', 'MemoryMax=450M', '-p', 'MemorySwapMax=0', '-p', 'CPUWeight=10', '-p', 'IOWeight=10', '-p', 'Nice=10',
		'-p', 'RuntimeMaxSec=1800'],
};

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

/* ---- 바깥 일: 도구 ---------------------------------------------------------- */

function sh(cmd, args, opts = {}) {
	const r = spawnSync(cmd, args, { encoding: 'utf8', env: ENV, maxBuffer: 64 * 1024 * 1024, ...opts });

	if (r.error && r.error.code !== 'ETIMEDOUT') {
		fail(`${cmd}: ${r.error.message}`);
	}

	return r;
}

function tail(text, n) {
	return String(text || '').trim().split('\n').slice(-n).join(' | ');
}

function must(cmd, args, opts = {}) {
	const r = sh(cmd, args, opts);

	if (r.status !== 0) {
		fail(`${path.basename(cmd)} ${args.find((a) => !a.startsWith('-')) || ''} failed: ${tail(r.stderr || r.stdout, 3)}`);
	}

	return r.stdout;
}

function sha256(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}

function sha256File(file) {
	try {
		return sha256(fs.readFileSync(file));
	} catch (e) {
		return null;
	}
}

function now() {
	return new Date().toISOString();
}

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function readLines(file) {
	let text;

	try {
		text = fs.readFileSync(file, 'utf8');
	} catch (e) {
		return [];
	}

	return text.split('\n').filter(Boolean).flatMap((l) => {
		try {
			return [JSON.parse(l)];
		} catch (e) {
			return [];	/* 쓰는 중인 마지막 줄 */
		}
	});
}

function writeJson(file, value, mode) {
	fs.writeFileSync(`${file}.tmp`, JSON.stringify(value, null, 1) + '\n', { mode });
	fs.renameSync(`${file}.tmp`, file);
}

function appendLog(log, text) {
	if (text) {
		fs.appendFileSync(log, text.endsWith('\n') ? text : `${text}\n`);
	}
}

function logTail(log) {
	try {
		return fs.readFileSync(log, 'utf8').trimEnd().split('\n').slice(-LOG_TAIL);
	} catch (e) {
		return [];
	}
}

function showUnit(name, props) {
	const r = sh('/usr/bin/systemctl', ['show', name, '--timestamp=unix', '-p', props.join(',')]);
	const p = {};

	for (const line of r.stdout.split('\n')) {
		const eq = line.indexOf('=');
		if (eq > 0) {
			p[line.slice(0, eq)] = line.slice(eq + 1);
		}
	}

	return p;
}

/* 지금의 작업 유닛. Description 에 작업 id 를 실어 띄운다. */
function deployUnit() {
	const p = showUnit(UNIT, ['ActiveState', 'Description']);
	const m = /^ztgate deploy (d-\S+)$/.exec(p.Description || '');

	return { active: ['active', 'activating', 'deactivating', 'reloading'].includes(p.ActiveState), job: m ? m[1] : null };
}

function serverUnit() {
	const p = showUnit(SERVER_UNIT, ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'NRestarts', 'Result',
		'ExecMainStatus', 'ExecMainStartTimestamp']);

	return {
		t: Date.now(),
		loaded: p.LoadState === 'loaded',
		state: p.ActiveState,
		sub: p.SubState,
		pid: Number(p.MainPID) || 0,
		restarts: Number(p.NRestarts) || 0,
		result: p.Result,
		exit_status: p.ExecMainStatus,
		started_at: /^@\d+$/.test(p.ExecMainStartTimestamp || '') ? Number(p.ExecMainStartTimestamp.slice(1)) * 1000 : 0,
	};
}

function account(name) {
	const line = fs.readFileSync('/etc/passwd', 'utf8').split('\n').find((l) => l.startsWith(`${name}:`));

	if (!line) {
		fail(`account ${name} is missing (mcp/install.sh creates it)`);
	}
	const f = line.split(':');

	return { uid: Number(f[2]), gid: Number(f[3]) };
}

/* 고정한 이름의 일회용 유닛에서 돌리고 끝날 때까지 기다린다. 출력은 작업의 log 로 간다 (systemd 가 root 로 연다).
 * --wait 는 유닛의 종료 코드를 그대로 돌려주지만 D-Bus 시스템 버스가 있어야 한다 (systemd 의 개인 소켓으로는 안 된다). */
function sandboxed(name, props, env, argv, log) {
	const r = sh('/usr/bin/systemd-run', ['--wait', '--collect', `--unit=${name}`, '-p', `BindsTo=${UNIT}`,
		'-p', `StandardOutput=append:${log}`, '-p', `StandardError=append:${log}`,
		...Object.entries(env).flatMap(([k, v]) => ['-E', `${k}=${v}`]), ...props, ...argv]);

	appendLog(log, r.stderr);

	return r.status;
}

/* ---- 바깥 일: 설정, 저장소 -------------------------------------------------- */

/* deploy.conf 는 root 소유이고 남이 쓸 수 없어야 한다. 서버 계정이 쓸 수 있는 /etc/ztgate 밖에 둔다 — 거기 두면
 * 서버를 차지한 쪽이 root 로 빌드할 코드를 고른다. */
function readConf() {
	let st;

	try {
		st = fs.statSync(CONF_FILE);
	} catch (e) {
		fail(`deploy is not set up on this host: ${CONF_FILE} is missing (mcp/install.sh writes it)`);
	}
	for (const [p, s] of [[ETC, fs.statSync(ETC)], [CONF_FILE, st]]) {
		if (s.uid !== 0 || (s.mode & 0o022) !== 0) {
			fail(`${p} must be owned by root and not writable by others`);
		}
	}

	return parseConf(fs.readFileSync(CONF_FILE, 'utf8'));
}

function gitEnv() {
	return { ...ENV, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', HOME: STATE, GIT_TERMINAL_PROMPT: '0' };
}

/* root 의 git 은 언제나 이 설정으로 돈다: 훅 없음, REPO 의 방식 하나만. */
function gitArgs(conf) {
	return ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
		'-c', `protocol.${conf.repo.startsWith('https://') ? 'https' : 'file'}.allow=always`, '-C', REPO_DIR];
}

function git(conf, args) {
	return must('/usr/bin/git', [...gitArgs(conf), ...args], { env: gitEnv() });
}

function gitTry(conf, args) {
	const r = sh('/usr/bin/git', [...gitArgs(conf), ...args], { env: gitEnv() });

	return r.status === 0 ? r.stdout.trim() : '';
}

function fetch(conf, log) {
	if (refspecs(conf).length === 0) {
		fail('deploy.conf allows no branch and no tag');
	}
	if (!fs.existsSync(`${REPO_DIR}/HEAD`)) {
		fs.mkdirSync(STATE, { recursive: true });
		must('/usr/bin/git', ['init', '--bare', '-q', REPO_DIR], { env: gitEnv() });
		fs.chmodSync(REPO_DIR, 0o700);
	}
	git(conf, ['config', 'remote.origin.url', conf.repo]);

	const status = sandboxed('ztgate-deploy-fetch', SANDBOX.fetch(), gitEnv(),
		['/usr/bin/git', ...gitArgs(conf), 'fetch', '--prune', '--no-tags', 'origin', ...refspecs(conf)], log);
	if (status !== 0) {
		fail(`git fetch from ${conf.repo} failed (exit status ${status}); see log_tail`);
	}
}

/* 가져온 저장소 안에서만 ref 를 커밋으로 푼다. */
function resolve(conf, input) {
	let commit;

	if (!refAllowed(conf, input)) {
		fail(`'${input.name}' is not an allowed branch or tag (branches: ${conf.branches.join(' ') || 'none'}; tags: ${conf.tags.join(' ') || 'none'})`);
	}
	if (input.kind === 'name') {
		const branch = conf.branches.some((p) => globMatch(p, input.name)) &&
			gitTry(conf, ['rev-parse', '--verify', '--quiet', `refs/remotes/origin/${input.name}^{commit}`]);
		const tag = !branch && conf.tags.some((p) => globMatch(p, input.name)) &&
			gitTry(conf, ['rev-parse', '--verify', '--quiet', `refs/tags/${input.name}^{commit}`]);

		commit = branch || tag;
		if (!commit) {
			fail(`no branch or tag '${input.name}' on ${conf.repo}`);
		}
	} else {
		commit = gitTry(conf, ['rev-parse', '--verify', '--quiet', `${input.prefix}^{commit}`]);
		if (!/^[0-9a-f]{40}$/.test(commit)) {
			fail(`no commit ${input.prefix} on an allowed branch or tag of ${conf.repo} (or the prefix is ambiguous)`);
		}
		const refs = gitTry(conf, ['for-each-ref', '--format=%(refname)', '--contains', commit, 'refs/remotes/origin', 'refs/tags'])
			.split('\n').filter((r) => r && refnameAllowed(conf, r));
		if (refs.length === 0) {
			fail(`commit ${commit.slice(0, 12)} is not reachable from an allowed branch or tag`);
		}
	}
	if (fs.existsSync(SIGNERS_FILE)) {
		const r = sh('/usr/bin/git', ['-c', 'gpg.format=ssh', '-c', `gpg.ssh.allowedSignersFile=${SIGNERS_FILE}`,
			...gitArgs(conf), 'verify-commit', commit], { env: gitEnv() });
		if (r.status !== 0) {
			fail(`commit ${commit.slice(0, 12)} is not signed by a key in ${SIGNERS_FILE}`);
		}
	}

	const version = gitTry(conf, ['cat-file', 'blob', `${commit}:VERSION`]);
	if (!/^\d+\.\d+\.\d+$/.test(version)) {
		fail(`commit ${commit.slice(0, 12)} has no VERSION`);
	}
	if (!gitTry(conf, ['cat-file', 'blob', `${commit}:packaging/build.sh`]).includes('SNAPSHOT')) {
		fail(`commit ${commit.slice(0, 12)} predates per-commit package versions (packaging/build.sh SNAPSHOT); it cannot be deployed`);
	}

	return {
		ref: input.kind === 'name' ? input.name : input.prefix,
		commit,
		version,
		snapshot: snapshotOf(Number(git(conf, ['log', '-1', '--format=%ct', commit]).trim()), commit),
		protocol: parseProtocol(gitTry(conf, ['cat-file', 'blob', `${commit}:lib/common/include/proto.h`])),
	};
}

/* ---- 바깥 일: 패키지 -------------------------------------------------------- */

/* 패키지 관리자 하나. rpm 과 deb 의 차이는 이 표에만 있다. 설치는 rpm -U / dpkg -i 로 파일을 바로 깐다 (dnf, apt 는
 * 저장소에서 의존성을 받으러 나가고, 실패했을 때 무엇이 바뀌었는지 흐려진다). */
const BACKENDS = {
	rpm: {
		ext: 'rpm',
		installedVersion() {
			const r = sh('/usr/bin/rpm', ['-q', '--qf', '%{VERSION}-%{RELEASE}', 'ztgate-server']);

			return r.status === 0 ? r.stdout.trim() : null;
		},
		inspect(file) {
			const [name, version, algo] = must('/usr/bin/rpm', ['-qp', '--nosignature', '--qf',
				'%{NAME}\t%{VERSION}-%{RELEASE}\t%{FILEDIGESTALGO}', file]).split('\t');
			const line = must('/usr/bin/rpm', ['-qp', '--nosignature', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\n]', file])
				.split('\n').find((l) => l.startsWith(`${SERVER_BIN}\t`));

			/* 8 = SHA-256 (RHEL 9 의 기본). 다른 알고리즘이면 도는 실행 파일과 견줄 수 없다. */
			return { name, version, server_sha256: algo === '8' && line ? line.split('\t')[1] : null };
		},
		install(file) {
			return sh('/usr/bin/rpm', ['-U', '--oldpackage', '--replacepkgs', file], { timeout: 300000 });
		},
	},
	deb: {
		ext: 'deb',
		installedVersion() {
			const r = sh('/usr/bin/dpkg-query', ['-W', '-f', '${db:Status-Status} ${Version}', 'ztgate-server']);
			const [status, version] = r.stdout.trim().split(' ');

			if (r.status !== 0 || !version) {
				return null;
			}

			/* 반쯤 깔린 패키지 (postinst 실패) 는 보관 패키지 어느 것과도 같지 않게 상태를 붙인다. */
			return status === 'installed' ? version : `${version} (${status})`;
		},
		inspect(file) {
			const f = Object.fromEntries(must('/usr/bin/dpkg-deb', ['-f', file, 'Package', 'Version']).trim().split('\n')
				.map((l) => l.split(': ')));
			const bin = sh('/bin/sh', ['-c', 'dpkg-deb --fsys-tarfile "$1" | tar -xOf - ".$2"', 'sh', file, SERVER_BIN],
				{ encoding: 'buffer' });

			return { name: f.Package, version: f.Version, server_sha256: bin.status === 0 && bin.stdout.length > 0 ? sha256(bin.stdout) : null };
		},
		install(file) {
			return sh('/usr/bin/dpkg', ['-i', file], { timeout: 300000, env: { ...ENV, DEBIAN_FRONTEND: 'noninteractive' } });
		},
	},
};

function backend() {
	return BACKENDS[fs.existsSync('/etc/debian_version') ? 'deb' : 'rpm'];
}

function keptList() {
	let names;

	try {
		names = fs.readdirSync(PACKAGES);
	} catch (e) {
		return [];
	}

	return names.filter((n) => /^[0-9a-f]{40}\.json$/.test(n)).flatMap((n) => {
		try {
			return [JSON.parse(fs.readFileSync(`${PACKAGES}/${n}`, 'utf8'))];
		} catch (e) {
			return [];
		}
	});
}

function keptFind(prefix) {
	const found = keptList().filter((k) => k.commit.startsWith(prefix));

	if (found.length !== 1) {
		fail(found.length === 0 ? `no kept package for commit ${prefix} (deploy_status lists them)` : `commit prefix ${prefix} is ambiguous`);
	}

	return found[0];
}

/* 패키지 DB 에서 끌어낸 지금 설치된 것. 적어 두지 않으므로 누가 손으로 rpm 을 깔아도 상태가 거짓말하지 않는다. */
function installed(be) {
	const version = be.installedVersion();

	if (version === null) {
		return { state: 'none' };
	}
	const kept = keptList().find((k) => k.kind === be.ext && k.version === version);

	return kept ? { state: 'kept', kept } : { state: 'foreign', version };
}

function short(inst) {
	if (inst.state !== 'kept') {
		return inst;
	}

	return { state: 'kept', commit: inst.kept.commit.slice(0, 12), version: inst.kept.version, protocol: inst.kept.protocol };
}

/* 빌드 계정의 폴더에서 패키지 하나를 root 의 보관소로 옮긴다. 링크는 따라가지 않고, 이름과 판이 기대한 값이 아니면
 * 버린다. 그 뒤로는 빌드 계정이 바꿀 수 없는 이 복사본만 믿는다. */
function keep(src, r, be, job) {
	const st = fs.lstatSync(src);
	if (!st.isFile()) {
		fail(`${src} is not a regular file`);
	}
	const fd = fs.openSync(src, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	const data = fs.readFileSync(fd);
	fs.closeSync(fd);

	const dst = `${PACKAGES}/${r.commit}.${be.ext}`;
	fs.mkdirSync(PACKAGES, { recursive: true, mode: 0o755 });
	fs.writeFileSync(`${dst}.tmp`, data, { mode: 0o644 });

	const p = be.inspect(`${dst}.tmp`);
	const want = versionOf(be.ext, r.version, r.snapshot);
	if (p.name !== 'ztgate-server' || p.version !== want) {
		fs.rmSync(`${dst}.tmp`, { force: true });
		fail(`the build made ${p.name} ${p.version}, expected ztgate-server ${want}`);
	}
	if (!/^[0-9a-f]{64}$/.test(p.server_sha256 || '')) {
		fs.rmSync(`${dst}.tmp`, { force: true });
		fail(`cannot read the sha256 of ${SERVER_BIN} in the package`);
	}

	const meta = {
		commit: r.commit, kind: be.ext, file: path.basename(dst), sha256: sha256(data), version: p.version,
		server_sha256: p.server_sha256, protocol: r.protocol, ref: r.ref, built_at: now(), build_job: job,
	};
	fs.renameSync(`${dst}.tmp`, dst);
	writeJson(`${PACKAGES}/${r.commit}.json`, meta, 0o644);

	return meta;
}

function build(conf, id, r, be, log) {
	const dir = `${BUILDS}/${id}`;
	const { uid, gid } = account(BUILD_USER);

	fs.rmSync(dir, { recursive: true, force: true });
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	fs.chownSync(dir, uid, gid);
	git(conf, ['archive', '--format=tar', '-o', `${dir}/src.tar`, r.commit]);

	const t0 = Date.now();
	const status = sandboxed('ztgate-deploy-build', SANDBOX.build(dir),
		{ KIND: be.ext, SNAPSHOT: r.snapshot, HOME: dir, PATH: ENV.PATH, LC_ALL: 'C' }, ['/bin/sh', '-ec', BUILD_SCRIPT], log);
	const sec = Math.round((Date.now() - t0) / 1000);
	const peak = /^memory_peak=(\d+)$/m.exec(fs.readFileSync(log, 'utf8'));

	if (status !== 0) {
		fs.rmSync(dir, { recursive: true, force: true });
		fail(`the build failed (exit status ${status}) after ${sec}s; see log_tail`);
	}

	const out = `${dir}/out`;
	const files = fs.lstatSync(out).isDirectory() ? fs.readdirSync(out).filter((f) => /^ztgate-server[-_].+\.(rpm|deb)$/.test(f)) : [];
	if (files.length !== 1) {
		fail(`the build left ${files.length} server packages, expected one`);
	}
	const kept = keep(`${out}/${files[0]}`, r, be, id);
	fs.rmSync(dir, { recursive: true, force: true });

	return { kept, sec, memory_peak: peak ? Number(peak[1]) : null };
}

/* ---- 바깥 일: 서버 검사 ----------------------------------------------------- */

function serverPort() {
	try {
		const m = /^\s*PORT=["']?(\d+)/m.exec(fs.readFileSync(SERVER_ENV, 'utf8'));
		return m ? Number(m[1]) : 9000;
	} catch (e) {
		return 9000;
	}
}

function sessionCount() {
	return new Promise((resolve) => {
		const sock = net.connect(STATUS_SOCK);
		let buf = '';

		sock.setTimeout(2000, () => sock.destroy(new Error('timeout')));
		sock.on('data', (d) => { buf += d; });
		sock.on('error', () => resolve(null));
		sock.on('end', () => {
			try {
				resolve(JSON.parse(buf).sessions.length);
			} catch (e) {
				resolve(null);
			}
		});
	});
}

/* 받지 않는 버전(255)의 REQ 한 통. 서버는 REQ 에 상태를 남기지 않고 VERSION (헤더 | min | max) 으로 답한다. */
function probeUdp(port) {
	return new Promise((resolve) => {
		const sock = dgram.createSocket('udp4');
		const req = Buffer.alloc(88);
		let tries = 0;
		let timer;
		let over = false;

		req[0] = 255;
		req[1] = 1;
		const done = (v) => {
			if (over) {
				return;
			}
			over = true;
			clearTimeout(timer);
			sock.close();
			resolve(v);
		};
		const send = () => {
			if (tries++ === 3) {
				done(null);
				return;
			}
			sock.send(req, port, '127.0.0.1');
			timer = setTimeout(send, 1000);
		};
		sock.on('message', (m) => {
			if (m.length >= 10 && m[1] === MSG_TYPE_VERSION) {
				done({ min: m[8], max: m[9] });
			}
		});
		sock.on('error', () => done(null));
		send();
	});
}

function ctlStatus(socket) {
	const r = sh(CTL, [], { input: JSON.stringify({ cmd: 'status', actor: 'deploy' }), timeout: 30000 });
	let out;

	try {
		out = JSON.parse(r.stdout);
	} catch (e) {
		return { ok: false, detail: `ztgate_ctl gave no answer: ${tail(r.stderr, 2) || `exit status ${r.status}`}` };
	}
	if (!out.ok) {
		return { ok: false, detail: `ztgate_ctl status: ${out.error}` };
	}
	if (socket && !Array.isArray(out.sessions)) {
		return { ok: false, detail: `ztgate_ctl status: ${out.sessions_error || 'no sessions from the status socket'}` };
	}

	return { ok: true, detail: socket ? `ok, status socket answers (${out.sessions.length} sessions)` : 'ok' };
}

/* 끝난 뒤 서버가 돌고 있었으면 새로 깐 실행 파일로 다시 떠 있게 한다. %post 는 active 일 때만 다시 올리므로,
 * 재시작을 반복하던 유닛 (되돌리기) 은 여기서 올린다. 멈춰 있던 서버는 띄우지 않는다. */
function ensureRestarted(since) {
	const u = serverUnit();

	if (u.state === 'active' && u.started_at >= since) {
		return;
	}
	sh('/usr/bin/systemctl', ['reset-failed', SERVER_UNIT]);
	sh('/usr/bin/systemctl', ['restart', SERVER_UNIT], { timeout: 90000 });
}

async function watchService(installedAt) {
	const samples = [serverUnit()];

	for (;;) {
		const s = settle(samples, installedAt, SETTLE_SEC, START_DEADLINE_SEC);
		if (s.state !== 'wait') {
			return { ...s, pid: samples[samples.length - 1].pid };
		}
		await sleep(1000);
		samples.push(serverUnit());
	}
}

/* 새 서버가 일한다는 증거. 서버가 멈춰 있었으면 서비스, 실행 파일, UDP 는 보지 않는다. 세션 수는 적기만 하고
 * 판정에 쓰지 않는다 (잠든 노트북은 돌아오지 않는다). */
async function healthCheck(kept, ctx) {
	const checks = [];
	const add = (name, ok, detail) => checks.push({ name, ok, detail });
	const version = backend().installedVersion();

	add('package', version === kept.version, version === kept.version ? kept.version : `installed is ${version || 'nothing'}, expected ${kept.version}`);

	let pid = 0;
	if (ctx.wasRunning) {
		const s = await watchService(ctx.installedAt);
		add('service', s.state === 'pass', s.detail);
		if (s.state === 'pass') {
			pid = s.pid;
			const exe = sha256File(`/proc/${pid}/exe`);
			add('binary', exe === kept.server_sha256, exe === kept.server_sha256
				? `pid ${pid} runs ${SERVER_BIN} of this package` : `pid ${pid} runs a different file (sha256 ${exe && exe.slice(0, 12)})`);
		}
	} else {
		add('service', null, 'the server was stopped before the deploy and stays stopped');
	}

	/* 상태 소켓까지 보는 것은 서비스가 통과했을 때뿐이다. 죽은 서버를 ctl 의 실패로 한 번 더 세지 않는다. */
	const c = ctlStatus(pid !== 0);
	add('ctl', c.ok, c.detail);

	if (pid && kept.protocol && kept.protocol.max >= 9) {
		const v = await probeUdp(serverPort());
		add('udp', v !== null, v ? `answers on udp/${serverPort()}, protocol ${v.min}..${v.max}` : `no VERSION answer on udp/${serverPort()}`);
	}
	if (ctx.serverKeySha) {
		const key = sha256File(SERVER_KEY);
		add('server_key', key === ctx.serverKeySha, key === ctx.serverKeySha ? 'unchanged' : `${SERVER_KEY} changed`);
	}

	const passed = checks.every((x) => x.ok !== false);
	const check = { passed, checks, sessions_before: ctx.sessionsBefore, sessions_after: pid ? await sessionCount() : null };
	if (!passed) {
		check.log_tail = sh('/usr/bin/journalctl', ['-u', SERVER_UNIT, '-n', '20', '--no-pager', '-o', 'cat']).stdout.trimEnd().split('\n');
	}

	return check;
}

/* ---- 바깥 일: 작업 ---------------------------------------------------------- */

function audit(e) {
	const line = { time: now().replace(/\.\d+Z$/, 'Z'), ...e };

	try {
		fs.appendFileSync(AUDIT_FILE, JSON.stringify(line) + '\n', { mode: 0o600 });
	} catch (err) {
		process.stderr.write(`ztgate-deploy: cannot write the audit log: ${err.code || err.name}\n`);
	}
}

function via() {
	return process.env.SUDO_USER && /^[A-Za-z0-9_.-]{1,32}$/.test(process.env.SUDO_USER) ? process.env.SUDO_USER : undefined;
}

function readRequest(id) {
	return JSON.parse(fs.readFileSync(`${JOBS}/${id}/request.json`, 'utf8'));
}

function jobIds() {
	try {
		return fs.readdirSync(JOBS).filter((n) => JOB_ID.test(n)).sort();
	} catch (e) {
		return [];
	}
}

function jobView(id, unit) {
	const req = readRequest(id);
	const v = reduceJob(req, readLines(`${JOBS}/${id}/events.jsonl`), unit, now());

	if (['fetching', 'building'].includes(v.phase) || ['failed', 'broken', 'interrupted'].includes(v.outcome)) {
		v.log_tail = logTail(`${JOBS}/${id}/log`);
	}
	if (v.target.commit) {
		v.target.commit = v.target.commit.slice(0, 12);
	}

	return v;
}

function history() {
	return readLines(HISTORY);
}

let stopping = false;

/* 작업 하나. 이 프로세스가 그 작업의 사건을 쓰는 유일한 쪽이다. 각 단계는 앞 단계가 "했다고 적은 것"이 아니라
 * 지금 있는 것 (보관소, 패키지 DB) 에서 시작하므로 같은 대상을 다시 돌려도 같은 끝에 닿는다. */
async function runJob(id) {
	if (!process.env.INVOCATION_ID || deployUnit().job !== id) {
		process.stderr.write(`ztgate-deploy: 'run' only runs inside ${UNIT} started for that job\n`);
		return 2;
	}
	process.on('SIGTERM', () => { stopping = true; });

	const req = readRequest(id);
	const log = `${JOBS}/${id}/log`;
	let view = initialView(req);
	const emit = (ev, fields = {}) => {
		const e = { t: now(), ev, ...fields };

		view = step(view, req, e);
		fs.appendFileSync(`${JOBS}/${id}/events.jsonl`, JSON.stringify(e) + '\n');
		/* 장비가 꺼지는 중이면 지금 단계까지 적고 멈춘다. 되돌리기를 새로 시작하지 않는다 (다음 status 가 interrupted). */
		if (stopping && ev !== 'finished') {
			process.exit(1);
		}
	};

	/* 죽은 작업이 남긴 빌드 폴더와 반쯤 쓴 보관 파일. 지금 도는 작업은 이것 하나뿐이다 (유닛 이름). */
	fs.rmSync(BUILDS, { recursive: true, force: true });
	fs.mkdirSync(BUILDS, { mode: 0o755 });
	for (const n of fs.existsSync(PACKAGES) ? fs.readdirSync(PACKAGES) : []) {
		if (n.endsWith('.tmp')) {
			fs.rmSync(`${PACKAGES}/${n}`, { force: true });
		}
	}

	const be = backend();
	const from = installed(be);
	const wasRunning = serverUnit().state === 'active';
	let target = null;

	const finish = (outcome, fields = {}) => {
		emit('finished', { outcome, ...fields });
		if (outcome === 'installed') {
			fs.appendFileSync(HISTORY, JSON.stringify({ t: now(), package: target.commit,
				from: from.state === 'kept' ? from.kept.commit : null, job: id }) + '\n');
		}
		if (req.kind !== 'build') {
			audit({ event: 'deploy', job: id, kind: req.kind, actor: req.actor, via: req.via, outcome,
				from: from.state === 'kept' ? from.kept.commit.slice(0, 12) : from.state,
				to: target ? target.commit.slice(0, 12) : (req.target.ref || null), error: fields.error });
		}
		prune(be, id);
		return 0;
	};

	emit('started', { from: short(from), was_running: wasRunning });

	try {
		if (req.kind === 'rollback') {
			target = keptFind(req.target.commit);
		} else {
			const conf = readConf();
			fetch(conf, log);
			const r = resolve(conf, wantRef(req.target.ref));
			emit('resolved', { commit: r.commit, version: versionOf(be.ext, r.version, r.snapshot), protocol: r.protocol });

			if (req.kind === 'deploy' && from.state === 'kept' && from.kept.commit === r.commit) {
				target = from.kept;
				return finish('unchanged', { note: 'this commit is already installed' });
			}
			target = keptList().find((k) => k.commit === r.commit && k.kind === be.ext) || null;
			if (target) {
				emit('reused', { package: r.commit });
			} else {
				emit('building');
				const b = build(conf, id, r, be, log);
				target = b.kept;
				emit('built', { package: r.commit, sec: b.sec, memory_peak: b.memory_peak });
			}
			if (req.kind === 'build') {
				return finish('built', { note: `${PACKAGES}/${target.file}` });
			}
		}

		if (from.state === 'kept' && from.kept.commit === target.commit) {
			return finish('unchanged', { note: 'this commit is already installed' });
		}
		if (from.state !== 'kept' && !req.accept.includes('no_revert')) {
			return finish('failed', { error: notKeptError(from) });
		}
		const risk = protocolRisk(from.state === 'kept' ? from.kept.protocol : null, target.protocol);
		if (risk && !req.accept.includes(risk)) {
			return finish('failed', { error: protocolError(from.kept.protocol, target.protocol) });
		}
	} catch (e) {
		return finish('failed', { error: errorText(e) });
	}

	return installAndCheck({ req, be, from, target, wasRunning, emit, finish });
}

function notKeptError(from) {
	return from.state === 'none'
		? 'no ztgate-server package is installed, so a failed check could not be undone; pass accept: ["no_revert"] to install anyway'
		: `the installed package (${from.version}) was not built by this deployer, so a failed check could not be undone; pass accept: ["no_revert"] to install anyway`;
}

function protocolError(from, to) {
	return `the target accepts protocol ${to.min}..${to.max} but the running server accepts ${from.min}..${from.max}: every connected client would be cut off (docs/decisions/0012-version-compat.md); pass accept: ["protocol_break"] to deploy anyway`;
}

function errorText(e) {
	return e instanceof DeployError ? e.message : `internal error: ${e.code || e.name}: ${e.message}`;
}

/* 깔고 검사하고, 떨어지면 출발점을 다시 깐다. 결과는 의도가 아니라 상태에서 정한다: 무엇이 깔렸는지는 매번
 * 패키지 DB 에서 다시 읽고, 출발점과 같으면 "바뀐 것 없음" (failed) 이다. 이 사이에는 ztgate_ctl 이 서버의
 * start / stop / restart 와 auth_check 를 거절한다 (WINDOW). */
async function installAndCheck({ req, be, from, target, wasRunning, emit, finish }) {
	const ctx = {
		wasRunning,
		serverKeySha: sha256File(SERVER_KEY),
		sessionsBefore: wasRunning ? await sessionCount() : null,
		installedAt: 0,
	};
	const put = (kept) => {
		ctx.installedAt = Math.floor(Date.now() / 1000) * 1000;
		const r = be.install(`${PACKAGES}/${kept.file}`);
		appendLog(`${JOBS}/${req.id}/log`, `$ ${be.ext} install ${kept.file} (exit status ${r.status})\n${r.stdout || ''}${r.stderr || ''}`);
		if (wasRunning) {
			ensureRestarted(ctx.installedAt);
		}
		return r;
	};
	const isNow = (kept) => {
		const i = installed(be);
		return i.state === 'kept' && i.kept.commit === kept.commit;
	};

	let backup = null;
	let changed = false;
	try {
		backup = fs.existsSync(BACKUP) && fs.existsSync(SERVER_ETC) ? tail(must(BACKUP, [], { timeout: 60000 }), 1) : null;
		emit('backed_up', { file: backup });
	} catch (e) {
		return finish('failed', { error: `ztgate-backup failed before the install: ${errorText(e)}` });
	}

	fs.mkdirSync(path.dirname(WINDOW), { recursive: true, mode: 0o755 });
	fs.writeFileSync(WINDOW, JSON.stringify({ job: req.id }) + '\n');
	try {
		const r = put(target);
		changed = from.state === 'kept' ? !isNow(from.kept) : installed(be).state !== from.state;
		if (isNow(target)) {
			emit('installed', { package: target.commit });
			const check = await healthCheck(target, ctx);
			emit('checked', { package: target.commit, check });
			if (check.passed) {
				return finish('installed');
			}
		} else if (!changed) {
			return finish('failed', { error: `${be.ext === 'rpm' ? 'rpm -U' : 'dpkg -i'} did not install the package (exit status ${r.status}): ${tail(r.stderr || r.stdout, 3)}; nothing changed` });
		}

		if (from.state !== 'kept') {
			return finish('broken', { error: 'the target failed its check and there is no kept package to go back to', note: brokenNext(backup) });
		}
		emit('reverting', { to: from.kept.commit });
		put(from.kept);
		if (!isNow(from.kept)) {
			return finish('broken', { error: `reinstalling ${from.kept.version} did not take`, note: brokenNext(backup) });
		}
		emit('installed', { package: from.kept.commit });
		const check = await healthCheck(from.kept, ctx);
		emit('checked', { package: from.kept.commit, check });

		return check.passed
			? finish('reverted', { note: `${target.commit.slice(0, 12)} failed its check; ${from.kept.commit.slice(0, 12)} is installed again and healthy. The ${target.commit.slice(0, 12)} package is kept for inspection.` })
			: finish('broken', { error: 'the previous package failed its check too', note: brokenNext(backup) });
	} catch (e) {
		const back = from.state === 'kept' && isNow(from.kept);
		return finish(back && !changed ? 'failed' : 'broken', { error: errorText(e), note: brokenNext(backup) });
	} finally {
		fs.rmSync(WINDOW, { force: true });
	}
}

function brokenNext(backup) {
	return [
		'sudo journalctl -u ztgate -n 50',
		...(backup ? [`sudo ztgate-backup restore ${backup}   # only if the configuration itself is damaged`] : []),
		'deploy_rollback with to=<another kept commit> (deploy_status lists them)',
	].join('\n');
}

/* 최근 KEEP 개의 보관 패키지와 JOB_KEEP 개의 작업만 남긴다. 지금 것과 이전 것은 지우지 않는다. */
function prune(be, current) {
	let conf;

	try {
		conf = readConf();
	} catch (e) {
		return;
	}
	const inst = installed(be);
	const cur = inst.state === 'kept' ? inst.kept.commit : null;
	const drop = pruneList(keptList(), history(), [cur, previousOf(history(), cur)].filter(Boolean), conf.keep);

	for (const c of drop) {
		const k = JSON.parse(fs.readFileSync(`${PACKAGES}/${c}.json`, 'utf8'));
		fs.rmSync(`${PACKAGES}/${k.file}`, { force: true });
		fs.rmSync(`${PACKAGES}/${c}.json`, { force: true });
	}
	for (const id of jobIds().slice(0, -JOB_KEEP)) {
		if (id !== current) {
			fs.rmSync(`${JOBS}/${id}`, { recursive: true, force: true });
		}
	}
}

/* ---- 요청 (sudo 로 부른 짧은 명령) ------------------------------------------ */

function wantAccept(v) {
	if (v === undefined) {
		return [];
	}
	if (!Array.isArray(v) || v.length > RISKS.length || v.some((r) => !RISKS.includes(r))) {
		fail(`accept must be a list of ${RISKS.join(', ')}`);
	}

	return [...new Set(v)];
}

function wantKeys(a, keys) {
	for (const k of Object.keys(a)) {
		if (!keys.includes(k)) {
			fail(`unknown field '${k}' (${keys.join(', ')})`);
		}
	}
}

function newJobId() {
	return `d-${now().slice(0, 19).replace(/[-:]/g, '')}Z-${crypto.randomBytes(2).toString('hex')}`;
}

/* 작업을 적고 유닛을 띄운다. 이미 도는 작업이 있으면 같은 대상이면 그 작업을 돌려주고 (답을 못 받은 호출자의
 * 재시도), 다르면 거절한다. 미리 보는 것은 친절이고, 규칙은 유닛 이름이다. */
function start(a) {
	const conf = readConf();
	const be = backend();
	const from = installed(be);
	const kind = { deploy: 'deploy', deploy_rollback: 'rollback', build: 'build' }[a.cmd];
	const accept = wantAccept(a.accept);
	let target;

	if (kind === 'rollback') {
		wantKeys(a, ['cmd', 'to', 'accept', 'actor']);
		if (a.to !== undefined && (typeof a.to !== 'string' || !/^[0-9a-f]{7,40}$/.test(a.to))) {
			fail('to must be 7-40 hex digits of a kept commit');
		}
		const cur = from.state === 'kept' ? from.kept.commit : null;
		const to = a.to || previousOf(history(), cur);
		if (!to) {
			fail('there is no previous package to go back to; give to=<commit> of a kept package (deploy_status lists them)');
		}
		const k = keptFind(to);
		target = { commit: k.commit, version: k.version };
	} else {
		wantKeys(a, ['cmd', 'ref', 'accept', 'actor']);
		const ref = wantRef(a.ref);
		if (!refAllowed(conf, ref)) {
			fail(`'${a.ref}' is not an allowed branch or tag in ${CONF_FILE} (branches: ${conf.branches.join(' ') || 'none'}; tags: ${conf.tags.join(' ') || 'none'})`);
		}
		target = { ref: a.ref };
	}
	if (kind !== 'build' && from.state !== 'kept' && !accept.includes('no_revert')) {
		fail(notKeptError(from));
	}

	const busy = (unit) => {
		const v = jobView(unit.job, unit);
		const same = v.kind === kind && (kind === 'rollback' ? v.target.commit === target.commit.slice(0, 12) : v.target.ref === target.ref);
		if (same) {
			return { job: v, already_running: true, next: 'call deploy_status with this job and wait_seconds (up to 150) until outcome is set' };
		}
		fail(`another deploy job is running (${unit.job}, ${v.kind}, phase ${v.phase}); follow it with deploy_status`);
	};
	const unit = deployUnit();
	if (unit.active && unit.job) {
		return busy(unit);
	}

	const id = newJobId();
	const req = { id, kind, target, accept, actor: wantActor(a.actor), via: via(), requested_at: now() };
	fs.mkdirSync(JOBS, { recursive: true, mode: 0o700 });
	fs.mkdirSync(`${JOBS}/${id}`, { mode: 0o700 });
	writeJson(`${JOBS}/${id}/request.json`, req, 0o600);

	const r = sh('/usr/bin/systemd-run', [`--unit=${UNIT}`, `--description=ztgate deploy ${id}`, '--collect', '--quiet',
		'-p', 'KillMode=mixed', '-p', 'TimeoutStopSec=300', '-p', 'RuntimeMaxSec=3600', process.execPath, __filename, 'run', id]);
	if (r.status !== 0) {
		fs.rmSync(`${JOBS}/${id}`, { recursive: true, force: true });
		const now2 = deployUnit();
		if (now2.active && now2.job) {
			return busy(now2);
		}
		fail(`cannot start ${UNIT}: ${tail(r.stderr, 2)}`);
	}

	return {
		job: jobView(id, { active: true, job: id }),
		from: short(from),
		next: 'call deploy_status with this job and wait_seconds (up to 150) until outcome is set',
	};
}

function wantActor(v) {
	return typeof v === 'string' && /^[A-Za-z0-9_.:@-]{1,64}$/.test(v) ? v : 'unknown';
}

/* 지금 설치된 것, 이전 것, 보관 패키지, 그리고 작업 하나 (주지 않으면 도는 것이나 마지막 것). wait_seconds 가
 * 있으면 그 작업이 끝날 때까지 1초마다 다시 읽으며 기다린다. */
async function status(a) {
	wantKeys(a, ['cmd', 'job', 'wait_seconds', 'actor']);
	if (a.job !== undefined && (typeof a.job !== 'string' || !JOB_ID.test(a.job) || !fs.existsSync(`${JOBS}/${a.job}/request.json`))) {
		fail('job must be a job id from deploy or deploy_rollback (deploy_status without job shows the latest)');
	}
	const wait = a.wait_seconds === undefined ? 0 : a.wait_seconds;
	if (!Number.isInteger(wait) || wait < 0 || wait > WAIT_MAX_SEC) {
		fail(`wait_seconds must be an integer in 0..${WAIT_MAX_SEC}`);
	}

	const t0 = Date.now();
	let unit = deployUnit();
	const id = a.job || (unit.active && unit.job) || jobIds().pop() || null;
	let job = id ? jobView(id, unit) : null;

	while (job && job.outcome === null && Date.now() - t0 < wait * 1000) {
		await sleep(1000);
		unit = deployUnit();
		job = jobView(id, unit);
	}

	const be = backend();
	const inst = installed(be);
	const cur = inst.state === 'kept' ? inst.kept.commit : null;
	const prev = previousOf(history(), cur);
	let conf = null;
	let why;

	try {
		conf = readConf();
	} catch (e) {
		why = errorText(e);
	}

	return {
		job,
		installed: short(inst),
		previous: prev ? { commit: prev.slice(0, 12), version: (keptList().find((k) => k.commit === prev) || {}).version || null } : null,
		running_job: unit.active ? unit.job : null,
		kept: keptList().sort((x, y) => y.built_at.localeCompare(x.built_at)).map((k) => ({
			commit: k.commit.slice(0, 12), version: k.version, ref: k.ref, built_at: k.built_at,
			...(k.commit === cur ? { installed: true } : {}), ...(k.commit === prev ? { previous: true } : {}),
		})),
		...(conf ? { remote: conf.repo, allowed: { branches: conf.branches, tags: conf.tags }, signed_only: fs.existsSync(SIGNERS_FILE) }
			: { enabled: false, why }),
		sync_primary: fs.existsSync(SYNC_MARK) ? fs.readFileSync(SYNC_MARK, 'utf8').trim() : null,
	};
}

async function serve() {
	let req;
	let out;

	try {
		req = JSON.parse(fs.readFileSync(0, 'utf8'));
		if (req === null || typeof req !== 'object' || !REQUESTS.includes(req.cmd)) {
			fail(`unknown command (${REQUESTS.join(', ')})`);
		}
		out = { ok: true, ...(req.cmd === 'deploy_status' ? await status(req) : start(req)) };
	} catch (e) {
		out = { ok: false, error: errorText(e) };
		if (!(e instanceof DeployError)) {
			process.stderr.write(`${e.stack}\n`);
		}
	}

	if (req && (req.cmd === 'deploy' || req.cmd === 'deploy_rollback')) {
		const asked = typeof req.ref === 'string' ? req.ref : req.to;
		audit({ event: 'admin', actor: wantActor(req.actor), via: via(), cmd: req.cmd, ok: out.ok,
			job: out.job ? out.job.id : undefined,
			target: out.job ? out.job.target.ref || out.job.target.commit : typeof asked === 'string' ? asked.slice(0, 100) : undefined,
			from: out.from ? out.from.commit || out.from.state : undefined,
			already_running: out.already_running, error: out.ok ? undefined : String(out.error).slice(0, 200) });
	}
	process.stdout.write(JSON.stringify(out) + '\n');

	return out.ok ? 0 : 1;
}

/* root 셸에서 첫 패키지를 빌드해 보관한다 (packaging/migrate-to-package.sh). 다른 작업과 같은 유닛, 같은 기록으로
 * 돌고 끝날 때까지 기다린다. */
async function buildCli(ref) {
	let r;

	try {
		r = start({ cmd: 'build', ref, actor: 'root' });
	} catch (e) {
		process.stderr.write(`ztgate-deploy: ${errorText(e)}\n`);
		return 1;
	}
	let v = r.job;
	while (v.outcome === null) {
		await sleep(2000);
		v = jobView(v.id, deployUnit());
	}
	process.stdout.write(JSON.stringify(v, null, 1) + '\n');

	return v.outcome === 'built' ? 0 : 1;
}

async function main(argv) {
	if (process.getuid() !== 0) {
		process.stderr.write('ztgate-deploy: must run as root (sudo -n ztgate-deploy)\n');
		return 2;
	}
	if (argv.length === 0) {
		return serve();
	}
	if (argv[0] === 'run' && argv.length === 2 && JOB_ID.test(argv[1])) {
		return runJob(argv[1]);
	}
	if (argv[0] === 'build' && argv.length === 2) {
		return buildCli(argv[1]);
	}
	process.stderr.write('usage: ztgate-deploy  (JSON on stdin) | run <job> | build <ref>\n');

	return 2;
}

if (require.main === module) {
	main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}

module.exports = {
	parseConf, wantRef, globMatch, refAllowed, refnameAllowed, refspecs, parseProtocol, protocolRisk, snapshotOf,
	versionOf, NEXT, OUTCOMES, REQUESTS, step, initialView, reduceJob, previousOf, pruneList, settle, DeployError,
};
