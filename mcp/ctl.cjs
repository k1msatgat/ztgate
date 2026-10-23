#!/usr/bin/node
/* ztgate_ctl — MCP 서버가 sudo 로 부르는 유일한 프로그램.
 *
 * MCP 서버(server.js)는 일반 계정으로 돌고 권한이 필요한 일은 전부 여기로 넘긴다.
 * sudoers 는 이 파일 하나만, 인자 없이 부르는 것만 허용한다. 그래서 MCP 쪽이 뚫려도
 * 할 수 있는 일은 아래 COMMANDS 에 있는 것이 전부다.
 *
 * 요청은 argv 가 아니라 stdin 의 JSON 한 덩어리로 받는다. 기기 키가 들어오는데
 * argv 는 ps 와 sudo 로그에 남는다.
 *
 * root 로 도는 코드라 npm 패키지를 쓰지 않는다. 호출한 쪽의 검증은 믿지 않고 여기서
 * 다시 한다. */
'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');

const UNIT = 'ztgate.service';
const ETC = '/etc/ztgate';
const DEVICE_FILE = `${ETC}/devices.conf`;
const ACL_FILE = `${ETC}/acl.conf`;
const ENROLL_FILE = `${ETC}/enroll.conf`;
const ENV_FILE = `${ETC}/server.env`;
const LOCK_FILE = `${ETC}/.ztgate.lock`;	/* server/src/enroll.c 의 config_lock 과 같은 파일 */
const ACL_APPLIED = '/run/ztgate/acl.applied';
const STATUS_SOCK = '/run/ztgate/status.sock';
const SERVER_BIN = '/opt/ztgate/server/bin/vpn_server';
const AUTH_CHECK = '/opt/ztgate/test/auth_check.py';
const AUDIT_FILE = '/var/log/ztgate/audit.log';
const AUDIT_EVENTS = ['session_open', 'session_close', 'auth_denied', 'access', 'reload', 'enrolled'];

/* 감사 로그는 계속 자란다. 통째로 읽지 않고 끝에서 이만큼만 본다. */
const AUDIT_TAIL_BYTES = 4 * 1024 * 1024;

/* server/include 의 값과 같아야 한다. */
const MAX_DEVICES = 4096;
const MAX_RULES = 1024;
const MAX_PENDING = 256;	/* server/include/enroll.h */
const ENROLL_CODE_LEN = 25;	/* lib/common/include/proto.h */
const ENROLL_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LINE_MAX = 255;	/* device.c / acl.c 가 한 줄을 char[256] 으로 읽는다 */

const ENV = { PATH: '/usr/sbin:/usr/bin', LC_ALL: 'C' };

class CtlError extends Error {}

function fail(msg) {
	throw new CtlError(msg);
}

function run(cmd, args, opts = {}) {
	const r = spawnSync(cmd, args, {
		encoding: 'utf8',
		env: ENV,
		maxBuffer: 64 * 1024 * 1024,
		...opts,
	});

	if (r.error && r.error.code !== 'ETIMEDOUT') {
		fail(`${cmd}: ${r.error.message}`);
	}

	return r;
}

/* ---- 입력 검증 ------------------------------------------------------------ */

function isIPv4(s) {
	return typeof s === 'string' &&
		/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(s) &&
		s.split('.').every((o) => Number(o) <= 255);
}

function isCidr(s) {
	if (s === 'any') {
		return true;
	}
	if (typeof s !== 'string') {
		return false;
	}

	const [ip, bits, extra] = s.split('/');
	if (extra !== undefined || !isIPv4(ip)) {
		return false;
	}

	return bits === undefined || (/^\d{1,2}$/.test(bits) && Number(bits) <= 32);
}

function isProto(s) {
	return ['any', 'icmp', 'tcp', 'udp'].includes(s) ||
		(typeof s === 'string' && /^\d{1,3}$/.test(s) && Number(s) <= 255);
}

function isPort(s) {
	if (s === 'any' || s === '-') {
		return true;
	}
	if (typeof s !== 'string' || !/^\d{1,5}(-\d{1,5})?$/.test(s)) {
		return false;
	}

	const [lo, hi = lo] = s.split('-').map(Number);

	return lo <= 65535 && hi <= 65535 && lo <= hi;
}

function wantInt(v, name, lo, hi) {
	if (!Number.isInteger(v) || v < lo || v > hi) {
		fail(`${name} must be an integer in ${lo}..${hi}`);
	}

	return v;
}

function wantId(v) {
	if (typeof v !== 'string' || !/^[0-9a-fA-F]{32}$/.test(v)) {
		fail('id must be 32 hex digits');
	}

	return v.toLowerCase();
}

/* 조건은 통째로 받는다. 빠진 항목은 "검사하지 않음"이다. */
function wantRequirements(v) {
	const r = { firewall: false, antivirus: false, min_build: 0 };

	if (v === undefined || v === null) {
		return r;
	}
	if (typeof v !== 'object' || Array.isArray(v)) {
		fail('requirements must be an object');
	}

	for (const k of Object.keys(v)) {
		if (!(k in r)) {
			fail(`unknown requirement '${k}' (firewall, antivirus, min_build)`);
		}
	}
	if (v.firewall !== undefined) {
		if (typeof v.firewall !== 'boolean') fail('requirements.firewall must be a boolean');
		r.firewall = v.firewall;
	}
	if (v.antivirus !== undefined) {
		if (typeof v.antivirus !== 'boolean') fail('requirements.antivirus must be a boolean');
		r.antivirus = v.antivirus;
	}
	if (v.min_build !== undefined) {
		r.min_build = wantInt(v.min_build, 'requirements.min_build', 0, 0xFFFFFFFF);
	}

	return r;
}

/* 조건을 파일에 쓰는 단어로. device.c / acl.c 가 같은 문법(policy.c)을 읽는다. */
function reqTokens(r) {
	const t = [];

	if (r.firewall) t.push('firewall=on');
	if (r.antivirus) t.push('antivirus=on');
	if (r.min_build > 0) t.push(`min-build=${r.min_build}`);

	return t;
}

/* 파일에서 읽은 단어를 조건으로. 모르는 단어면 null. */
function parseReq(tokens) {
	const r = { firewall: false, antivirus: false, min_build: 0 };

	for (const t of tokens) {
		const m = /^min-build=(\d+)$/.exec(t);

		if (t === 'firewall=on') {
			r.firewall = true;
		} else if (t === 'antivirus=on') {
			r.antivirus = true;
		} else if (m) {
			r.min_build = Number(m[1]);
		} else {
			return null;
		}
	}

	return r;
}

function reqEmpty(r) {
	return !r.firewall && !r.antivirus && r.min_build === 0;
}

/* 이름은 줄 끝의 주석으로 들어간다. '#' 나 줄바꿈이 섞이면 파일 형식이 깨진다. */
function wantLabel(v) {
	if (v === undefined || v === null || v === '') {
		return '';
	}
	if (typeof v !== 'string' || !/^[A-Za-z0-9_.-]([A-Za-z0-9 _.-]{0,30}[A-Za-z0-9_.-])?$/.test(v)) {
		fail('label must be 1-32 characters of letters, digits, space, _ . -');
	}

	return v;
}

/* ---- 설정 파일 ------------------------------------------------------------ */

function readEnv() {
	const env = { PORT: '9000', TUN_IP: '10.0.0.1', PREFIX: '24', MTU: '1400' };
	let text;

	try {
		text = fs.readFileSync(ENV_FILE, 'utf8');
	} catch (e) {
		return env;
	}

	for (const line of text.split('\n')) {
		const m = /^\s*([A-Z_]+)=(.*)$/.exec(line);
		if (m) {
			env[m[1]] = m[2].trim();
		}
	}

	return env;
}

/* 같은 디렉터리에 쓰고 rename 한다. 쓰다가 죽어도 반쯤 쓰인 기기 목록이 남지 않고,
 * 그 사이에 SIGHUP 을 받은 서버가 잘린 파일을 읽을 일도 없다. */
function writeAtomic(path, text) {
	const tmp = `${path}.tmp.${process.pid}`;

	fs.writeFileSync(tmp, text, { mode: 0o600 });
	fs.renameSync(tmp, path);
}

function readDevices() {
	const devices = [];
	let text;

	try {
		text = fs.readFileSync(DEVICE_FILE, 'utf8');
	} catch (e) {
		if (e.code === 'ENOENT') {
			return devices;
		}
		throw e;
	}

	text.split('\n').forEach((raw, i) => {
		const hash = raw.indexOf('#');
		const body = hash < 0 ? raw : raw.slice(0, hash);
		const label = hash < 0 ? '' : raw.slice(hash + 1).trim();
		const tok = body.trim().split(/\s+/).filter(Boolean);
		const d = {};

		if (tok.length === 0) {
			return;
		}
		if (tok.length < 3 || !/^[0-9a-fA-F]{32}$/.test(tok[0]) ||
				!/^[0-9a-fA-F]{64}$/.test(tok[1]) || !isIPv4(tok[2])) {
			fail(`${DEVICE_FILE}: line ${i + 1} is malformed; fix it by hand first`);
		}

		d.id = tok[0].toLowerCase();
		d.key = tok[1].toLowerCase();
		d.tunnel_ip = tok[2];
		d.label = /^[A-Za-z0-9 _.-]{1,32}$/.test(label) ? label : '';

		/* 커넥터의 대역은 반드시 들고 다닌다. 빠뜨리면 기기 목록을 다시 쓰는 순간 커넥터가
		 * 평범한 기기가 되고, 그 대역으로 가는 길이 사라진다. */
		const conds = splitConnector(tok.slice(3));
		d.connector = conds.connector;
		d.requirements = parseReq(conds.rest);
		if (d.requirements === null) {
			fail(`${DEVICE_FILE}: line ${i + 1}: unknown requirement; fix it by hand first`);
		}

		devices.push(d);
	});

	return devices;
}

function writeDevices(devices) {
	const lines = [
		'# ztgate 기기 목록. MCP(ztgate_ctl)가 관리한다 — 손으로 고쳐도 되지만 주석은 줄 끝의',
		'# 이름표만 남는다. 형식은 README 의 "설정 파일".',
		'#',
		'# id (32 hex)  key (64 hex)  tunnel-ip  requirements  # label',
	];

	for (const d of devices) {
		let line = [d.id, d.key, d.tunnel_ip, ...reqTokens(d.requirements),
			...(d.connector || []).map((c) => `connector=${c}`)].join(' ');

		if (d.label) {
			line += `  # ${d.label}`;
		}
		if (Buffer.byteLength(line) > LINE_MAX - 1) {
			fail('device line too long');
		}
		lines.push(line);
	}

	writeAtomic(DEVICE_FILE, lines.join('\n') + '\n');
}

/* 키는 어떤 응답에도 넣지 않는다. */
function publicDevice(d) {
	const p = { id: d.id, label: d.label, tunnel_ip: d.tunnel_ip, requirements: d.requirements };

	if (d.connector && d.connector.length > 0) {
		p.connector = d.connector;
	}
	return p;
}

/* ---- 등록 코드 -------------------------------------------------------------
 * 기기의 ID 와 키를 손으로 옮기는 대신, 관리자가 코드 하나를 만들어 건넨다. 코드에서
 * 뽑은 임시 신원을 대기 목록에 적어 두면 서버가 그 코드로 온 기기를 받아 기기 목록에
 * 올리고 그 줄을 지운다 (server/include/enroll.h, lib/common/include/proto.h). */

/* secure.c 의 secure_enroll_identity 와 같아야 한다. 양쪽 selftest 와 auth_check.py 가
 * 같은 값을 확인한다. */
function enrollIdentity(code) {
	const hmac = (label) => crypto.createHmac('sha256', label).update(code, 'ascii').digest();

	return {
		id: hmac('ztgate enroll id').subarray(0, 16).toString('hex'),
		key: hmac('ztgate enroll key').toString('hex'),
	};
}

/* 0-9 와 헷갈리는 글자(I L O U)를 뺀 대문자 32개, 25자. 한 글자가 5비트라 125비트다.
 * randomInt 는 치우침 없이 뽑는다 (Math.random 은 암호용이 아니다). */
function newEnrollCode() {
	let code = '';

	for (let i = 0; i < ENROLL_CODE_LEN; i++) {
		code += ENROLL_ALPHABET[crypto.randomInt(ENROLL_ALPHABET.length)];
	}

	return code;
}

function readEnroll() {
	const now = Math.floor(Date.now() / 1000);
	const list = [];
	let text;

	try {
		text = fs.readFileSync(ENROLL_FILE, 'utf8');
	} catch (e) {
		if (e.code === 'ENOENT') {
			return list;
		}
		throw e;
	}

	for (const raw of text.split('\n')) {
		const hash = raw.indexOf('#');
		const tok = (hash < 0 ? raw : raw.slice(0, hash)).trim().split(/\s+/).filter(Boolean);
		const label = hash < 0 ? '' : raw.slice(hash + 1).trim();

		if (tok.length < 4 || !/^[0-9a-f]{32}$/.test(tok[0]) || !/^[0-9a-f]{64}$/.test(tok[1]) ||
				!isIPv4(tok[2]) || !/^\d+$/.test(tok[3])) {
			continue;
		}
		/* 만료된 줄은 여기서 빠진다. 다음에 쓸 때 파일에서도 사라진다. */
		if (Number(tok[3]) <= now) {
			continue;
		}

		list.push({
			id: tok[0],
			key: tok[1],
			tunnel_ip: tok[2],
			expires: Number(tok[3]),
			requirements: parseReq(splitConnector(tok.slice(4)).rest) || { firewall: false, antivirus: false, min_build: 0 },
			connector: splitConnector(tok.slice(4)).connector,
			label: /^[A-Za-z0-9 _.-]{1,32}$/.test(label) ? label : '',
		});
	}

	return list;
}

function writeEnroll(list) {
	const lines = [
		'# ztgate 등록 대기 목록. 관리 도구가 줄을 더하고 서버가 쓰인 줄을 지운다.',
		'# id (32 hex)  key (64 hex)  tunnel-ip  expires (unix)  requirements  # label',
	];

	for (const e of list) {
		let line = [e.id, e.key, e.tunnel_ip, e.expires, ...reqTokens(e.requirements),
			...(e.connector || []).map((c) => `connector=${c}`)].join(' ');

		if (e.label) {
			line += `  # ${e.label}`;
		}
		lines.push(line);
	}

	writeAtomic(ENROLL_FILE, lines.join('\n') + '\n');
}

/* 키는 어떤 응답에도 넣지 않는다. id 는 코드가 아니라 코드에서 뽑은 이름표라 내줘도
 * 그것으로 등록할 수는 없다. 대기 중인 코드를 가리켜 취소할 때 쓴다. */
function publicEnroll(e) {
	return {
		id: e.id,
		label: e.label,
		tunnel_ip: e.tunnel_ip,
		requirements: e.requirements,
		...(e.connector && e.connector.length > 0 ? { connector: e.connector } : {}),
		expires_in_sec: e.expires - Math.floor(Date.now() / 1000),
	};
}

function ipToInt(s) {
	return s.split('.').reduce((n, o) => n * 256 + Number(o), 0);
}

function intToIp(n) {
	return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/* 터널 대역에서 아직 아무도 쓰지 않는 가장 낮은 주소. 서버의 주소, 등록된 기기의 주소,
 * 다른 코드가 맡아 둔 주소를 뺀다. */
function freeTunnelIp(devices, pending) {
	const env = readEnv();
	const prefix = Number(env.PREFIX);
	const size = 2 ** (32 - prefix);
	const net = Math.floor(ipToInt(env.TUN_IP) / size) * size;
	const used = new Set([env.TUN_IP, ...devices.map((d) => d.tunnel_ip), ...pending.map((e) => e.tunnel_ip)]);

	/* 첫 주소(대역 자신)와 마지막 주소(브로드캐스트)는 기기에 주지 않는다. */
	for (let n = net + 1; n < net + size - 1; n++) {
		if (!used.has(intToIp(n))) {
			return intToIp(n);
		}
	}

	fail('no free address left in the tunnel subnet');
}

/* 커넥터가 맡은 대역: 기기 줄의 connector=10.101.0.0/16 (server/include/device.h). 조건이 아니라
 * 기기의 역할이라 requirements 와 따로 둔다. 서버와 같은 규칙으로 본다 — /0 은 안 되고, 주소의
 * 호스트 부분은 0 이어야 한다. */
const CONNECTOR_MAX_NETS = 4;

function isConnectorNet(s) {
	if (typeof s !== 'string' || !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(s)) {
		return false;
	}
	const [ip, bits] = s.split('/');
	const n = Number(bits);
	if (!isIPv4(ip) || n < 1 || n > 32) {
		return false;
	}
	const host = n === 32 ? 0 : (2 ** (32 - n)) - 1;
	return (ipToInt(ip) % (host + 1)) === 0;
}

/* 줄의 조건 단어들을 connector= 와 나머지로 나눈다. */
function splitConnector(tokens) {
	return {
		connector: tokens.filter((t) => t.startsWith('connector=')).map((t) => t.slice(10)),
		rest: tokens.filter((t) => !t.startsWith('connector=')),
	};
}

function wantConnector(v) {
	if (v === undefined || v === null) {
		return [];
	}
	if (!Array.isArray(v) || v.length > CONNECTOR_MAX_NETS || !v.every(isConnectorNet)) {
		fail(`connector must be a list of at most ${CONNECTOR_MAX_NETS} networks like "10.101.0.0/16" (no /0, host bits zero)`);
	}
	return v;
}

/* ACL 규칙의 사용자 조건: user=alice / group=dev (server/include/policy.h). 이름에 쓸 수 있는
 * 글자와 규칙 하나에 적을 수 있는 수도 서버와 같다. */
const USER_NAME = /^[A-Za-z0-9._@+\/-]{1,63}$/;
const USER_REQ_MAX = 4;

function isUserToken(t) {
	return t.startsWith('user=') || t.startsWith('group=');
}

function parseUsers(tokens) {
	const u = { users: [], groups: [] };

	for (const t of tokens) {
		if (t.startsWith('user=')) {
			u.users.push(t.slice(5));
		} else {
			u.groups.push(t.slice(6));
		}
	}

	return u;
}

function wantUsers(v, i) {
	const u = { users: [], groups: [] };

	if (v === undefined || v === null) {
		return u;
	}
	if (typeof v !== 'object' || Array.isArray(v)) {
		fail(`rule ${i}: users must be an object { users: [...], groups: [...] }`);
	}
	for (const k of Object.keys(v)) {
		if (k !== 'users' && k !== 'groups') {
			fail(`rule ${i}: unknown key '${k}' in users (users, groups)`);
		}
		if (!Array.isArray(v[k]) || !v[k].every((n) => typeof n === 'string' && USER_NAME.test(n))) {
			fail(`rule ${i}: users.${k} must be names of letters, digits and . _ @ + - / (at most 63)`);
		}
		u[k] = v[k];
	}
	if (u.users.length + u.groups.length > USER_REQ_MAX) {
		fail(`rule ${i}: at most ${USER_REQ_MAX} users and groups per rule`);
	}

	return u;
}

function readAcl() {
	let text;

	try {
		text = fs.readFileSync(ACL_FILE, 'utf8');
	} catch (e) {
		if (e.code === 'ENOENT') {
			return null;
		}
		throw e;
	}

	const rules = [];

	for (const raw of text.split('\n')) {
		const tok = raw.replace(/#.*/, '').trim().split(/\s+/).filter(Boolean);

		if (tok.length >= 5) {
			const rule = { src: tok[0], dst: tok[1], proto: tok[2], dport: tok[3], action: tok[4] };
			const conds = tok.slice(5);
			const require = parseReq(conds.filter((t) => !isUserToken(t)));
			const users = parseUsers(conds.filter(isUserToken));

			if (require !== null && !reqEmpty(require)) {
				rule.require = require;
			}
			/* 사용자 조건은 반드시 돌려준다. 빠뜨리면 acl_get 으로 읽어 고친 뒤 acl_set 으로
			 * 쓰는 순간 "alice 만"이던 규칙이 모두에게 열린다. */
			if (users.users.length + users.groups.length > 0) {
				rule.users = users;
			}
			rules.push(rule);
		}
	}

	return rules;
}

function aclHash() {
	try {
		return crypto.createHash('sha256').update(fs.readFileSync(ACL_FILE)).digest('hex');
	} catch (e) {
		return 'none';
	}
}

/* 서버가 지금 쓰고 있는 ACL 의 해시. service.sh 가 시작할 때 적고, 다시 읽기에
 * 성공하면 reload() 가 고쳐 적는다. ACL 없이 뜬 서버는 'none' 이다. */
function aclApplied() {
	try {
		return fs.readFileSync(ACL_APPLIED, 'utf8').trim();
	} catch (e) {
		return null;
	}
}

/* 파일은 바뀌었는데 서버는 아직 예전 규칙으로 도는 상태. 규칙을 고친 것은 SIGHUP 으로
 * 적용되지만, ACL 을 켜고 끄는 것은 서버를 다시 띄워야 한다 — 서버는 시작할 때 규칙
 * 파일을 받았는지로 ACL 을 쓸지 정하고, 도는 중에는 그걸 바꾸지 않는다. */
function aclPending(running) {
	const applied = aclApplied();

	return running && applied !== null && applied !== aclHash();
}

/* 파일의 끝 max 바이트. 중간부터 읽었으면 첫 줄은 잘려 있으므로 버린다. */
function readTail(path, max) {
	const fd = fs.openSync(path, 'r');

	try {
		const size = fs.fstatSync(fd).size;
		const start = Math.max(0, size - max);
		const buf = Buffer.alloc(size - start);
		const n = fs.readSync(fd, buf, 0, buf.length, start);
		const text = buf.toString('utf8', 0, n);

		return start === 0 ? text : text.slice(text.indexOf('\n') + 1);
	} finally {
		fs.closeSync(fd);
	}
}

/* ---- systemd / journal ---------------------------------------------------- */

function unit() {
	const r = run('/usr/bin/systemctl', ['show', UNIT, '--timestamp=unix',
		'-p', 'LoadState,ActiveState,SubState,MainPID,InvocationID,Result,ExecMainStatus,UnitFileState,ExecMainStartTimestamp']);
	const p = {};

	for (const line of r.stdout.split('\n')) {
		const eq = line.indexOf('=');
		if (eq > 0) {
			p[line.slice(0, eq)] = line.slice(eq + 1);
		}
	}
	if (p.LoadState !== 'loaded') {
		fail(`${UNIT} is not installed (run mcp/install.sh)`);
	}

	p.running = p.ActiveState === 'active';

	return p;
}

function journal(args) {
	const r = run('/usr/bin/journalctl', ['--no-pager', '-q', '-o', 'json', ...args]);
	const out = [];

	for (const line of r.stdout.split('\n')) {
		let e;

		if (!line) {
			continue;
		}
		try {
			e = JSON.parse(line);
		} catch (err) {
			continue;
		}
		if (typeof e.MESSAGE === 'string') {
			out.push({
				time: new Date(Number(e.__REALTIME_TIMESTAMP) / 1000).toISOString(),
				msg: e.MESSAGE,
			});
		}
	}

	return out;
}

function tailLog(n) {
	return journal(['-u', UNIT, '-n', String(n)]).map((e) => `${e.time} ${e.msg}`);
}

/* 서버에게 직접 묻는다. 상태 소켓은 접속하면 JSON 한 덩어리를 쓰고 닫는다
 * (server/include/status.h). 세션 목록과 판정 횟수는 서버의 피어 테이블에서 바로
 * 나온 값이다. */
function serverStatus() {
	return new Promise((resolve) => {
		const sock = net.connect(STATUS_SOCK);
		let buf = '';

		sock.setTimeout(2000, () => sock.destroy(new Error('timeout')));
		sock.on('data', (d) => { buf += d; });
		sock.on('error', () => resolve(null));
		sock.on('end', () => {
			try {
				resolve(JSON.parse(buf));
			} catch (e) {
				resolve(null);
			}
		});
	});
}

/* 왜 거절됐는지는 숫자가 아니라 문장으로 남는다. 그건 로그에서 읽는다. */
function rejections(invocation) {
	if (!invocation) {
		return [];
	}

	return journal([`_SYSTEMD_INVOCATION_ID=${invocation}`, '--grep', '^\\[(HS|ka|deny)\\] '])
		.filter((e) => /rejected|bad auth|unknown device|no longer registered|not its tunnel ip|^\[deny\]/.test(e.msg))
		.slice(-5)
		.map((e) => `${e.time} ${e.msg}`);
}

function tunnel(pid) {
	let dev = null;

	try {
		for (const fd of fs.readdirSync(`/proc/${pid}/fdinfo`)) {
			const m = /^iff:\s*(\S+)/m.exec(fs.readFileSync(`/proc/${pid}/fdinfo/${fd}`, 'utf8'));
			if (m) {
				dev = m[1];
				break;
			}
		}
	} catch (e) {
		return null;
	}
	if (dev === null) {
		return null;
	}

	try {
		const link = JSON.parse(run('/usr/sbin/ip', ['-j', 'addr', 'show', 'dev', dev]).stdout)[0];
		const a = (link.addr_info || []).find((x) => x.family === 'inet');

		return {
			device: dev,
			address: a ? `${a.local}/${a.prefixlen}` : null,
			mtu: link.mtu,
			up: (link.flags || []).includes('UP'),
		};
	} catch (e) {
		return { device: dev };
	}
}

async function status() {
	const u = unit();
	const env = readEnv();
	const acl = readAcl();
	const st = {
		running: u.running,
		state: `${u.ActiveState}/${u.SubState}`,
		start_at_boot: u.UnitFileState === 'enabled',
		listen: `udp/${env.PORT}`,
		tunnel_address: `${env.TUN_IP}/${env.PREFIX}`,
		registered_devices: readDevices().length,
		acl: {
			enabled: acl !== null,
			rules: acl === null ? 0 : acl.length,
			restart_required: aclPending(u.running),
		},
	};

	if (u.running) {
		st.pid = Number(u.MainPID);
		st.started_at = new Date(Number(u.ExecMainStartTimestamp.slice(1)) * 1000).toISOString();
		st.tunnel = tunnel(u.MainPID);

		const live = await serverStatus();
		if (live === null) {
			st.sessions_error = 'the server did not answer on its status socket';
		} else {
			st.uptime_sec = live.uptime_sec;
			st.sessions = live.sessions;
			st.counters = live.counters;
		}
		st.recent_rejections = rejections(u.InvocationID);
	} else if (u.ActiveState === 'failed') {
		st.last_result = `${u.Result} (exit status ${u.ExecMainStatus})`;
		st.last_log = tailLog(15);
	}

	return st;
}

function systemctl(verb) {
	const r = run('/usr/bin/systemctl', [verb, UNIT], { timeout: 30000 });

	if (r.status !== 0) {
		fail(`systemctl ${verb} failed: ${(r.stderr || '').trim()}\n--- last log\n${tailLog(15).join('\n')}`);
	}
}

/* SIGHUP 을 보내고 서버가 실제로 새 목록을 받아들였는지 로그로 확인한다. 서버는
 * 파일이 마음에 들지 않으면 이전 목록을 그대로 쓰는데, 그걸 모르고 "적용됨"이라고
 * 답하면 폐기했다고 믿은 기기가 계속 붙어 있게 된다. */
function reload() {
	const u = unit();
	const filter = [`_SYSTEMD_INVOCATION_ID=${u.InvocationID}`, '--grep', '^(device|acl): reload'];
	let before, now, i, acl, dev, aclLive;

	if (!u.running) {
		return { reloaded: false, note: 'server is not running; the new files are read at the next start' };
	}

	/* ACL 을 켠 채 뜬 서버만 ACL 을 다시 읽고, 그때는 결과를 두 줄 찍는다. */
	aclLive = aclApplied() !== 'none';
	before = journal(filter).length;
	systemctl('reload');

	/* 서버는 epoll 타임아웃(1초)마다 요청을 확인한다. */
	for (i = 0; i < 30; i++) {
		now = journal(filter).slice(before);
		dev = now.find((e) => e.msg.startsWith('device:'));
		acl = now.find((e) => e.msg.startsWith('acl:'));
		if (dev && (acl || !aclLive)) {
			break;
		}
		spawnSync('/usr/bin/sleep', ['0.1']);
	}
	if (i === 30) {
		fail('sent SIGHUP but the server did not report a reload within 3s');
	}

	if (dev.msg.includes('failed')) {
		fail('server rejected the device file and kept the previous list');
	}
	if (acl && !acl.msg.includes('failed')) {
		fs.writeFileSync(ACL_APPLIED, aclHash() + '\n');
	} else if (acl && fs.existsSync(ACL_FILE)) {
		fail('server rejected the ACL file and kept the previous rules');
	}

	return {
		reloaded: true,
		note: 'ACL rules apply from the next packet; open sessions are re-evaluated against the device list at their next keepalive (within 10s)',
	};
}

/* ---- 명령 ------------------------------------------------------------------ */

/* 기기 목록과 등록 대기 목록은 서버도 고친다 (등록 코드로 기기가 올라올 때). 읽고 → 고치고 →
 * 새 파일로 바꾸는 사이에 서로 끼면 먼저 쓴 쪽이 고친 것이 사라진다. 그 파일을 고치는 명령은
 * 서버와 같은 잠금(LOCK_FILE 의 flock)을 잡고 돈다.
 *
 * Node 에는 flock 이 없어 flock(1) 이 잠금을 쥔 채 표준 입력을 기다리게 하고, 끝나면 그
 * 표준 입력을 닫는다. 이 프로세스가 죽어도 flock(1) 이 EOF 를 보고 끝나 잠금이 남지 않는다.
 * 서버는 200ms 만 기다리므로 잠금 안에서는 파일을 고치는 것만 한다 — 서버에 다시 읽게 하고
 * 그 결과를 기다리는 것(최대 3초)은 풀고 나서 한다 (명령이 [RELOAD] 를 돌려주면 main 이). */
const LOCKED_COMMANDS = new Set(['device_add', 'device_update', 'device_remove', 'enroll_create', 'enroll_revoke']);
const RELOAD = Symbol('reload');

function withConfigLock(fn) {
	return new Promise((resolve, reject) => {
		const holder = spawn('flock', ['-x', '-w', '5', LOCK_FILE, 'sh', '-c', 'echo locked; exec cat > /dev/null'],
			{ env: ENV, stdio: ['pipe', 'pipe', 'ignore'] });
		let held = false;

		holder.stdout.once('data', () => {
			held = true;
			try {
				resolve(fn());
			} catch (e) {
				reject(e);
			} finally {
				holder.stdin.end();
			}
		});
		holder.on('exit', (code) => {
			if (!held) {
				reject(new CtlError(code === 1 ? 'the device files are being changed by the server; try again'
					: 'cannot lock the device files (flock)'));
			}
		});
		holder.on('error', () => reject(new CtlError('cannot lock the device files (flock(1) not found)')));
	});
}

const COMMANDS = {
	status() {
		return status();	/* Promise — main 이 기다린다 */
	},

	async start() {
		if (unit().running) {
			return { changed: false, ...await status() };
		}
		systemctl('start');
		return { changed: true, ...await status() };
	},

	async stop() {
		const was = unit().running;

		systemctl('stop');
		/* 시작에 실패한 유닛은 stop 뒤에도 failed 로 남는다. 내리라고 했으면 지운다. */
		run('/usr/bin/systemctl', ['reset-failed', UNIT]);
		return { changed: was, ...await status() };
	},

	async restart() {
		systemctl('restart');
		return { changed: true, ...await status() };
	},

	reload() {
		return reload();
	},

	logs(a) {
		const lines = a.lines === undefined ? 50 : wantInt(a.lines, 'lines', 1, 500);
		const args = ['-u', UNIT];
		let out;

		if (a.contains !== undefined && typeof a.contains !== 'string') {
			fail('contains must be a string');
		}
		if (a.since_seconds !== undefined) {
			args.push('--since', `-${wantInt(a.since_seconds, 'since_seconds', 1, 7 * 86400)}s`);
		}
		/* 걸러 낼 때는 넉넉히 읽고 뒤에서 자른다. 패킷마다 한 줄씩 찍히는 로그라
		 * 마지막 N 줄만 읽어서는 찾는 줄이 거의 남지 않는다. */
		args.push('-n', a.contains ? '20000' : String(lines));

		out = journal(args);
		if (a.contains) {
			out = out.filter((e) => e.msg.includes(a.contains));
		}

		return { lines: out.slice(-lines).map((e) => `${e.time} ${e.msg}`) };
	},

	/* 감사 로그는 서버가 직접 쓰는 파일이다 (server/include/audit.h). 한 줄이 사건 하나의
	 * JSON 이라 그대로 읽어 걸러서 돌려준다. journal 의 로그와 달리 재시작해도 이어지고,
	 * 패킷마다가 아니라 사건마다 한 줄이다. */
	audit(a) {
		const lines = a.lines === undefined ? 50 : wantInt(a.lines, 'lines', 1, 500);
		const device = a.device === undefined ? null : wantId(a.device);
		const since = a.since_seconds === undefined ? null :
			Date.now() - wantInt(a.since_seconds, 'since_seconds', 1, 30 * 86400) * 1000;
		const events = [];
		let text;

		if (a.event !== undefined && !AUDIT_EVENTS.includes(a.event)) {
			fail(`event must be one of ${AUDIT_EVENTS.join(', ')}`);
		}

		try {
			text = readTail(AUDIT_FILE, AUDIT_TAIL_BYTES);
		} catch (e) {
			if (e.code === 'ENOENT') {
				return { events, note: 'no audit log yet; the server creates it when it starts' };
			}
			throw e;
		}

		for (const line of text.split('\n')) {
			let e;

			if (!line) {
				continue;
			}
			try {
				e = JSON.parse(line);
			} catch (err) {
				continue;	/* 서버가 쓰는 중인 마지막 줄 */
			}
			if ((a.event && e.event !== a.event) || (device && e.device !== device) ||
					(since !== null && Date.parse(e.time) < since)) {
				continue;
			}
			events.push(e);
		}

		return { events: events.slice(-lines) };
	},

	device_list() {
		return { devices: readDevices().map(publicDevice) };
	},

	device_add(a) {
		const devices = readDevices();
		const d = {
			id: wantId(a.id),
			key: a.key,
			tunnel_ip: a.tunnel_ip,
			requirements: wantRequirements(a.requirements),
			label: wantLabel(a.label),
		};

		if (typeof d.key !== 'string' || !/^[0-9a-fA-F]{64}$/.test(d.key)) {
			fail('key must be 64 hex digits');
		}
		d.key = d.key.toLowerCase();

		if (!isIPv4(d.tunnel_ip)) {
			fail('tunnel_ip must be an IPv4 address');
		}
		if (d.tunnel_ip === readEnv().TUN_IP) {
			fail(`tunnel_ip ${d.tunnel_ip} is the server's own tunnel address`);
		}
		if (devices.length >= MAX_DEVICES) {
			fail(`device list is full (max ${MAX_DEVICES})`);
		}
		if (devices.some((x) => x.id === d.id)) {
			fail('a device with this id is already registered');
		}
		if (devices.some((x) => x.tunnel_ip === d.tunnel_ip)) {
			fail(`tunnel_ip ${d.tunnel_ip} is already assigned`);
		}
		/* 발급해 둔 등록 코드가 맡아 둔 주소. 여기에 다른 기기를 올리면 그 코드는 쓸 수 없게 된다. */
		if (readEnroll().some((x) => x.tunnel_ip === d.tunnel_ip)) {
			fail(`tunnel_ip ${d.tunnel_ip} is reserved by a pending enrollment code (enroll_list)`);
		}

		devices.push(d);
		writeDevices(devices);

		return { device: publicDevice(d), [RELOAD]: true };
	},

	device_update(a) {
		const devices = readDevices();
		const id = wantId(a.id);
		const d = devices.find((x) => x.id === id);

		if (!d) {
			fail('no device with this id');
		}
		if (a.requirements !== undefined) {
			d.requirements = wantRequirements(a.requirements);
		}
		if (a.label !== undefined) {
			d.label = wantLabel(a.label);
		}
		if (a.tunnel_ip !== undefined) {
			if (!isIPv4(a.tunnel_ip)) {
				fail('tunnel_ip must be an IPv4 address');
			}
			if (a.tunnel_ip === readEnv().TUN_IP) {
				fail(`tunnel_ip ${a.tunnel_ip} is the server's own tunnel address`);
			}
			if (devices.some((x) => x !== d && x.tunnel_ip === a.tunnel_ip)) {
				fail(`tunnel_ip ${a.tunnel_ip} is already assigned`);
			}
			d.tunnel_ip = a.tunnel_ip;
		}

		writeDevices(devices);

		return { device: publicDevice(d), [RELOAD]: true };
	},

	/* 코드는 이 응답에서 한 번만 나온다. 파일에는 코드에서 뽑은 값만 남는다. */
	enroll_create(a) {
		const devices = readDevices();
		const pending = readEnroll();
		const ttl = a.ttl_minutes === undefined ? 15 : wantInt(a.ttl_minutes, 'ttl_minutes', 1, 1440);
		const requirements = wantRequirements(a.requirements);
		const connector = wantConnector(a.connector);
		const label = wantLabel(a.label);
		const code = newEnrollCode();
		let tunnelIp = a.tunnel_ip;

		if (devices.length + pending.length >= MAX_DEVICES) {
			fail(`device list is full (max ${MAX_DEVICES}, counting pending enrollments)`);
		}
		if (pending.length >= MAX_PENDING) {
			fail(`too many pending enrollments (max ${MAX_PENDING}); revoke one or wait for it to expire`);
		}

		if (tunnelIp === undefined) {
			tunnelIp = freeTunnelIp(devices, pending);
		} else {
			if (!isIPv4(tunnelIp)) {
				fail('tunnel_ip must be an IPv4 address');
			}
			if (tunnelIp === readEnv().TUN_IP) {
				fail(`tunnel_ip ${tunnelIp} is the server's own tunnel address`);
			}
			if (devices.some((x) => x.tunnel_ip === tunnelIp) || pending.some((x) => x.tunnel_ip === tunnelIp)) {
				fail(`tunnel_ip ${tunnelIp} is already assigned`);
			}
		}

		const entry = {
			...enrollIdentity(code),
			tunnel_ip: tunnelIp,
			expires: Math.floor(Date.now() / 1000) + ttl * 60,
			requirements,
			connector,
			label,
		};

		writeEnroll([...pending, entry]);

		return {
			/* 다섯 자씩 끊어 준다. 사람이 읽어 주거나 받아 적는 값이다. */
			code: code.match(/.{5}/g).join('-'),
			enrollment: publicEnroll(entry),
			how: 'On the device: "vpn_client.exe enroll <server-ip> <port> <code>", or the GUI posture tab -> enroll. The code works once.',
			[RELOAD]: true,
		};
	},

	enroll_list() {
		return { pending: readEnroll().map(publicEnroll) };
	},

	enroll_revoke(a) {
		const pending = readEnroll();
		const id = wantId(a.id);
		const left = pending.filter((e) => e.id !== id);

		if (left.length === pending.length) {
			fail('no pending enrollment with this id (it may have been used or expired)');
		}

		writeEnroll(left);

		return { revoked: id, [RELOAD]: true };
	},

	device_remove(a) {
		const devices = readDevices();
		const id = wantId(a.id);
		const left = devices.filter((x) => x.id !== id);

		if (left.length === devices.length) {
			fail('no device with this id');
		}

		writeDevices(left);

		return { removed: id, [RELOAD]: true };
	},

	acl_get() {
		const rules = readAcl();
		const running = unit().running;

		return {
			enabled: rules !== null,
			rules: rules || [],
			restart_required: aclPending(running),
			note: 'first matching rule wins; no match means deny. An allow rule with a require denies the packet when the last reported posture of the session falls short (later rules are not tried); likewise an allow rule with users only admits sessions where one of those users (or a member of one of those groups) is logged in with an unexpired token. Applies to client -> server packets only. Rule changes apply without a restart; turning the ACL on or off needs server_restart.',
		};
	},

	acl_set(a) {
		const lines = ['# ztgate ACL. MCP(ztgate_ctl)가 관리한다. 형식은 README 의 "설정 파일".',
			'# src  dst  proto  dport  action'];

		if (!Array.isArray(a.rules) || a.rules.length === 0) {
			fail('rules must be a non-empty array (use acl_clear to turn the ACL off)');
		}
		if (a.rules.length > MAX_RULES) {
			fail(`too many rules (max ${MAX_RULES})`);
		}

		a.rules.forEach((r, i) => {
			const dport = r && r.dport !== undefined ? r.dport : 'any';

			if (!r || typeof r !== 'object') fail(`rule ${i}: must be an object`);
			if (!isCidr(r.src)) fail(`rule ${i}: bad src '${r.src}' (a.b.c.d, a.b.c.d/n, any)`);
			if (!isCidr(r.dst)) fail(`rule ${i}: bad dst '${r.dst}' (a.b.c.d, a.b.c.d/n, any)`);
			if (!isProto(r.proto)) fail(`rule ${i}: bad proto '${r.proto}' (icmp, tcp, udp, any, 0-255)`);
			if (!isPort(dport)) fail(`rule ${i}: bad dport '${dport}' (n, lo-hi, any)`);
			if (r.action !== 'allow' && r.action !== 'deny') fail(`rule ${i}: action must be allow or deny`);

			const require = wantRequirements(r.require);
			if (r.action === 'deny' && !reqEmpty(require)) {
				fail(`rule ${i}: require is only for allow rules`);
			}
			const users = wantUsers(r.users, i);
			if (r.action === 'deny' && users.users.length + users.groups.length > 0) {
				fail(`rule ${i}: users is only for allow rules`);
			}

			lines.push([r.src, r.dst, r.proto, dport, r.action, ...reqTokens(require),
				...users.users.map((n) => `user=${n}`), ...users.groups.map((n) => `group=${n}`)].join(' '));
		});

		writeAtomic(ACL_FILE, lines.join('\n') + '\n');

		/* ACL 을 켠 채 돌고 있는 서버에는 바로 적용한다. ACL 없이 뜬 서버는 다시
		 * 읽어도 켜지지 않으므로 restart_required 로 남는다. */
		if (unit().running && aclApplied() !== 'none') {
			reload();
		}

		return COMMANDS.acl_get();
	},

	acl_clear() {
		fs.rmSync(ACL_FILE, { force: true });

		return COMMANDS.acl_get();
	},

	/* auth_check.py 는 자기 서버를 따로 띄워 tun 에 10.0.0.1/24 를 붙인다. 운영 서버와
	 * 같은 대역이라 둘이 함께 돌 수 없다. */
	auth_check() {
		let r;

		if (unit().running || run('/usr/bin/pgrep', ['-x', 'vpn_server']).status === 0) {
			fail('a vpn_server is running; stop it first (the check starts its own server on the same tunnel subnet)');
		}

		r = run('/usr/bin/python3', ['-I', AUTH_CHECK], { timeout: 180000, cwd: '/' });

		return {
			passed: r.status === 0,
			output: (r.stdout || '') + (r.stderr || ''),
		};
	},
};

async function main() {
	let req, out;

	if (process.getuid() !== 0) {
		process.stderr.write('ztgate_ctl: must run as root (sudo -n ztgate_ctl)\n');
		return 2;
	}
	if (process.argv.length > 2) {
		process.stderr.write('ztgate_ctl: takes no arguments; send {"cmd": ...} on stdin\n');
		return 2;
	}

	try {
		req = JSON.parse(fs.readFileSync(0, 'utf8'));
		if (req === null || typeof req !== 'object' || !Object.hasOwn(COMMANDS, req.cmd)) {
			fail(`unknown command (${Object.keys(COMMANDS).join(', ')})`);
		}
		let r = LOCKED_COMMANDS.has(req.cmd)
			? await withConfigLock(() => COMMANDS[req.cmd](req))
			: await COMMANDS[req.cmd](req);
		if (r[RELOAD]) {
			delete r[RELOAD];
			r = { ...r, ...reload() };
		}
		out = { ok: true, ...r };
	} catch (e) {
		/* 예상한 실패만 그대로 전한다. 그 밖의 예외는 경로 같은 내부 사정을 담고
		 * 있을 수 있으니 종류만 알린다. */
		out = { ok: false, error: e instanceof CtlError ? e.message : `internal error: ${e.code || e.name}` };
		if (!(e instanceof CtlError)) {
			process.stderr.write(`${e.stack}\n`);
		}
	}

	process.stdout.write(JSON.stringify(out) + '\n');

	return out.ok ? 0 : 1;
}

main().then((code) => { process.exitCode = code; });
