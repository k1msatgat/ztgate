/* ztgate-deploy 의 순수한 부분: node --test mcp/deploy.test.cjs */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('./deploy.cjs');

const C40 = (c) => c.repeat(40);

test('deploy.conf: defaults, keys, and refusals', () => {
	assert.deepEqual(d.parseConf('# empty\n'), { repo: 'https://github.com/k1msatgat/ztgate.git', branches: ['*'], tags: ['v*'], keep: 5 });
	assert.deepEqual(d.parseConf('REPO=file:///srv/r.git\nBRANCHES=main  wip/*\nTAGS=\nKEEP=3\n'),
		{ repo: 'file:///srv/r.git', branches: ['main', 'wip/*'], tags: [], keep: 3 });
	assert.equal(d.parseConf('REPO=/srv/r.git').repo, '/srv/r.git');
	for (const bad of ['FOO=1', 'REPO=git@github.com:k1msatgat/ztgate.git', 'REPO=http://example.com/x.git',
		'REPO=https://example.com/x.git;rm', 'KEEP=0', 'KEEP=51', 'BRANCHES=a*b*', 'BRANCHES=../x', 'BRANCHES=-x', 'just text']) {
		assert.throws(() => d.parseConf(bad), d.DeployError, bad);
	}
});

test('ref names and commits from the caller', () => {
	assert.deepEqual(d.wantRef('9272113'), { kind: 'commit', prefix: '9272113' });
	assert.deepEqual(d.wantRef('ABCDEF0123'), { kind: 'commit', prefix: 'abcdef0123' });
	assert.deepEqual(d.wantRef('fix/icmp-frag'), { kind: 'name', name: 'fix/icmp-frag' });
	assert.deepEqual(d.wantRef('v0.9.4'), { kind: 'name', name: 'v0.9.4' });
	for (const bad of ['', '-x', '/x', 'x/', 'a..b', 'a//b', 'a/.b', 'x.lock', 'a b', 'a~1', 'a^', 'x'.repeat(101), 42, null]) {
		assert.throws(() => d.wantRef(bad), d.DeployError, String(bad));
	}
});

test('allow-list: names against BRANCHES and TAGS, fetched refs against the same list', () => {
	const conf = d.parseConf('BRANCHES=main wip/*\nTAGS=v*\n');

	assert.equal(d.refAllowed(conf, d.wantRef('main')), true);
	assert.equal(d.refAllowed(conf, d.wantRef('wip/a/b')), true, '* crosses / like a git refspec');
	assert.equal(d.refAllowed(conf, d.wantRef('v0.9.4')), true);
	assert.equal(d.refAllowed(conf, d.wantRef('mainx')), false);
	assert.equal(d.refAllowed(conf, d.wantRef('evil')), false);
	assert.equal(d.refAllowed(conf, d.wantRef('deadbeef')), true, 'a commit is judged by reachability after the fetch');

	assert.equal(d.refnameAllowed(conf, 'refs/remotes/origin/main'), true);
	assert.equal(d.refnameAllowed(conf, 'refs/remotes/origin/evil'), false, 'a ref left from an older allow-list does not count');
	assert.equal(d.refnameAllowed(conf, 'refs/tags/v1'), true);
	assert.equal(d.refnameAllowed(conf, 'refs/heads/main'), false);

	assert.deepEqual(d.refspecs(conf), ['+refs/heads/main:refs/remotes/origin/main',
		'+refs/heads/wip/*:refs/remotes/origin/wip/*', '+refs/tags/v*:refs/tags/v*']);
	assert.equal(d.globMatch('v1.*', 'v1x2'), false, '. is literal');
});

test('protocol range from proto.h, and when a deploy would cut every client off (ADR 0012)', () => {
	assert.deepEqual(d.parseProtocol('#define PROTOCOL_VERSION 10 /* x */\n#define PROTOCOL_VERSION_MIN 9\n'), { min: 9, max: 10 });
	assert.deepEqual(d.parseProtocol('#define PROTOCOL_VERSION 8\n'), { min: 8, max: 8 });
	assert.equal(d.parseProtocol(''), null);

	assert.equal(d.protocolRisk({ min: 9, max: 9 }, { min: 9, max: 10 }), null);
	assert.equal(d.protocolRisk({ min: 9, max: 10 }, { min: 10, max: 11 }), null);
	assert.equal(d.protocolRisk({ min: 9, max: 9 }, { min: 10, max: 11 }), 'protocol_break');
	assert.equal(d.protocolRisk({ min: 10, max: 11 }, { min: 9, max: 9 }), 'protocol_break', 'rolling back below the clients');
	assert.equal(d.protocolRisk(null, { min: 9, max: 9 }), null);
});

test('package version per commit: the same as packaging/build.sh SNAPSHOT', () => {
	const commit = '9272113abcdef0123456789abcdef0123456789a';
	const snap = d.snapshotOf(Date.UTC(2026, 9, 31, 4, 59, 3) / 1000, commit);

	assert.equal(snap, '20261031045903.g9272113abcde');
	assert.equal(d.snapshotOf(Date.UTC(2026, 9, 31, 4, 59, 3) / 1000, commit), snap, 'same commit, same value');
	assert.equal(d.versionOf('rpm', '0.9.4', snap), '0.9.4-0.20261031045903.g9272113abcde');
	assert.equal(d.versionOf('deb', '0.9.4', snap), '0.9.4~20261031045903.g9272113abcde');
});

const T0 = Date.parse('2026-10-31T03:00:00Z');
const at = (s) => new Date(T0 + s * 1000).toISOString();
const req = (kind = 'deploy', target = { ref: 'main' }) =>
	({ id: 'd-20261031T030000Z-7c1e', kind, target, accept: [], actor: 'mcp', requested_at: at(0) });
const pass = { passed: true, checks: [] };
const failed = { passed: false, checks: [{ name: 'service', ok: false, detail: 'restarted 3 time(s)' }] };
const mine = { active: true, job: 'd-20261031T030000Z-7c1e' };
const none = { active: false, job: null };
const deployed = [
	{ t: at(1), ev: 'started', from: { state: 'kept', commit: 'aaaaaaaaaaaa' }, was_running: true },
	{ t: at(4), ev: 'resolved', commit: C40('b'), version: '0.9.4-0.x', protocol: { min: 9, max: 9 } },
	{ t: at(5), ev: 'building' },
	{ t: at(150), ev: 'built', package: C40('b'), sec: 145, memory_peak: 300e6 },
	{ t: at(152), ev: 'backed_up', file: '/var/backups/ztgate/x.tar.gz' },
	{ t: at(160), ev: 'installed', package: C40('b') },
];

test('job view: phases come from the events', () => {
	const queued = d.reduceJob(req(), [], mine, at(0));
	assert.equal(queued.phase, 'queued');
	assert.equal(queued.outcome, null);

	const building = d.reduceJob(req(), deployed.slice(0, 3), mine, at(60));
	assert.equal(building.phase, 'building');
	assert.equal(building.outcome, null);
	assert.equal(building.target.commit, C40('b'));
	assert.equal(building.elapsed_sec, 60);

	const done = d.reduceJob(req(), [...deployed, { t: at(176), ev: 'checked', package: C40('b'), check: pass },
		{ t: at(176), ev: 'finished', outcome: 'installed' }], none, at(999));
	assert.equal(done.phase, 'done');
	assert.equal(done.outcome, 'installed');
	assert.deepEqual(done.phases.map((p) => p.phase), ['queued', 'fetching', 'building', 'backing_up', 'installing', 'checking']);
	assert.equal(done.phases.find((p) => p.phase === 'building').sec, 145);
	assert.equal(done.backup, '/var/backups/ztgate/x.tar.gz');
	assert.deepEqual(done.check, pass);
	assert.equal(done.elapsed_sec, 176, 'elapsed stops at the end');
});

test('job view: a failed check and the revert keep both reports', () => {
	const v = d.reduceJob(req(), [...deployed,
		{ t: at(180), ev: 'checked', package: C40('b'), check: failed },
		{ t: at(180), ev: 'reverting', to: C40('a') },
		{ t: at(190), ev: 'installed', package: C40('a') },
		{ t: at(206), ev: 'checked', package: C40('a'), check: pass },
		{ t: at(206), ev: 'finished', outcome: 'reverted', note: 'x' }], none, at(999));

	assert.equal(v.outcome, 'reverted');
	assert.deepEqual(v.check, failed);
	assert.deepEqual(v.revert_check, pass);
	assert.deepEqual(v.phases.map((p) => p.phase).slice(-3), ['checking', 'reverting', 'checking']);
});

test('job view: a rollback skips fetching and building', () => {
	const v = d.reduceJob(req('rollback', { commit: C40('a') }), [
		{ t: at(1), ev: 'started', from: { state: 'kept' }, was_running: true },
		{ t: at(2), ev: 'backed_up', file: null }], mine, at(3));
	assert.equal(v.phase, 'installing');
	assert.throws(() => d.step(d.initialView(req('rollback')), req('rollback'), { t: at(1), ev: 'building' }), d.DeployError);
});

test('job view: a job whose unit is gone without an end is interrupted, and says how far it got', () => {
	const v = d.reduceJob(req(), deployed.slice(0, 3), none, at(60));
	assert.equal(v.outcome, 'interrupted');
	assert.equal(v.phase, 'building');

	assert.equal(d.reduceJob(req(), [], none, at(5)).outcome, 'interrupted', 'never started');
	assert.equal(d.reduceJob(req(), deployed.slice(0, 3), { active: true, job: 'd-20261031T040000Z-0000' }, at(60)).outcome,
		'interrupted', 'the unit now runs another job');
});

test('job view: an impossible event order is reported, not thrown', () => {
	const v = d.reduceJob(req(), [{ t: at(1), ev: 'installed', package: C40('b') }], mine, at(2));
	assert.match(v.error, /cannot follow phase 'queued'/);
	assert.throws(() => d.step(d.initialView(req()), req(), { t: at(1), ev: 'installed' }), d.DeployError);
});

test('previous package: what the current one replaced, never a reverted attempt', () => {
	const h = [
		{ t: at(1), package: 'A', from: null },
		{ t: at(2), package: 'B', from: 'A' },	/* then C failed its check and B came back: no line */
	];
	assert.equal(d.previousOf(h, 'B'), 'A');
	assert.equal(d.previousOf(h, 'A'), null);
	assert.equal(d.previousOf([...h, { t: at(3), package: 'A', from: 'B' }], 'A'), 'B', 'a rollback flips previous');
	assert.equal(d.previousOf(h, null), null);
});

test('pruning kept packages: newest KEEP stay, the installed and previous ones always stay', () => {
	const kept = ['1', '2', '3', '4', '5', '6', '7'].map((c, i) => ({ commit: c, built_at: at(i) }));

	assert.deepEqual(d.pruneList(kept, [], [], 5).sort(), ['1', '2']);
	assert.deepEqual(d.pruneList(kept, [], ['1'], 5), ['2']);
	assert.deepEqual(d.pruneList(kept, [{ t: at(100), package: '2' }], [], 5).sort(), ['1', '3'], 'installing counts as recent use');
	assert.deepEqual(d.pruneList(kept.slice(0, 3), [], [], 5), []);
});

const sample = (s, o = {}) => ({ t: T0 + s * 1000, state: 'active', sub: 'running', pid: 100, restarts: 0, result: 'success',
	exit_status: '0', started_at: T0, ...o });

test('service check: steady for the settle time passes', () => {
	const steady = Array.from({ length: 16 }, (_, s) => sample(s));
	assert.equal(d.settle(steady.slice(0, 10), T0, 15, 60).state, 'wait');
	assert.equal(d.settle(steady, T0, 15, 60).state, 'pass');

	const late = [sample(0, { state: 'activating', sub: 'start', pid: 0 }), ...Array.from({ length: 16 }, (_, s) => sample(s + 1, { pid: 200 }))];
	assert.equal(d.settle(late, T0, 15, 60).state, 'pass');
	assert.match(d.settle(late, T0, 15, 60).detail, /same pid 200/);
});

test('service check: a restart, a failed unit, the old process, or no steady state fails', () => {
	const r = d.settle([sample(0), sample(1, { state: 'activating', sub: 'auto-restart', restarts: 1, exit_status: '3' })], T0, 15, 60);
	assert.equal(r.state, 'fail');
	assert.match(r.detail, /restarted 1 time\(s\).*exit status 3/);

	assert.equal(d.settle([sample(0, { state: 'failed', result: 'exit-code', exit_status: '1' })], T0, 15, 60).state, 'fail');
	assert.match(d.settle([sample(0, { started_at: T0 - 5000 })], T0, 15, 60).detail, /from before the install/);

	const flapping = Array.from({ length: 61 }, (_, s) => sample(s, { pid: 100 + s }));
	assert.equal(d.settle(flapping, T0, 15, 60).state, 'fail');
});
