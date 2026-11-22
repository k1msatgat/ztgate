/* ztgate_ctl 이 파일에 쓰기 전에 거절해야 하는 요청: node --test mcp/ctl.test.cjs
 * 거절하는 길만 부른다. 받아들이는 요청은 /etc/ztgate 에 쓰러 가므로 여기서 부르지 않는다. */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { COMMANDS } = require('./ctl.cjs');

function p256Hex() {
	const jwk = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

	return Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex');
}

test('device_add: a p256: key that is not a point on P-256 is refused', () => {
	const good = p256Hex();
	const offCurve = good.slice(0, 127) + (good[127] === '0' ? '1' : '0');

	for (const key of [`p256:${offCurve}`, `p256:${'0'.repeat(128)}`]) {
		assert.throws(() => COMMANDS.device_add({ id: 'ab'.repeat(16), key, tunnel_ip: '10.0.0.5' }), /not a P-256 public key/, key);
	}
});

test('enroll_create: conditions, tags and connector ranges longer than the server takes are refused', () => {
	const req = {
		requirements: { firewall: true, antivirus: true, disk: true, min_build: 4294967295 },
		tags: [1, 2, 3, 4].map((i) => `${'t'.repeat(31)}${i}`),
		connector: ['10.101.0.0/16', '10.102.0.0/16', '10.103.0.0/16', '10.104.0.0/16'],
	};

	assert.throws(() => COMMANDS.enroll_create(req), /too long/);
});

test('acl_set: a rule longer than an ACL line the server reads is refused', () => {
	const rule = {
		src: '255.255.255.255/32', dst: '255.255.255.255/32', proto: 'tcp', dport: '65535-65535', action: 'allow',
		require: { firewall: true, antivirus: true, disk: true, min_build: 4294967295 },
		users: { groups: [1, 2, 3, 4].map((i) => `${'g'.repeat(62)}${i}`) },
		tags: [1, 2, 3, 4].map((i) => `${'t'.repeat(31)}${i}`),
	};

	assert.throws(() => COMMANDS.acl_set({ rules: [rule] }), /rule 0: .*too long/);
});

/* /etc/ztgate, /run/ztgate, /var/log/ztgate 는 서버 계정 소유다. 그 안의 이름이 링크나 FIFO 로 바뀌어 있어도
 * root 인 ztgate_ctl 이 따라가 남의 파일을 읽거나 쓰지 않는다. */
test('files in the server account\'s folders: links and FIFOs are not followed', { skip: process.platform === 'win32' }, () => {
	const fs = require('node:fs');
	const os = require('node:os');
	const { spawnSync } = require('node:child_process');
	const ctl = require('./ctl.cjs');
	const dir = fs.mkdtempSync(`${os.tmpdir()}/ctl-test-`);
	const victim = `${dir}/victim`;

	try {
		fs.writeFileSync(victim, 'secret\n');
		for (const name of ['acl.applied', 'audit.log', '.sync-primary']) {
			fs.symlinkSync(victim, `${dir}/${name}`);
		}
		assert.throws(() => ctl.writeOwned(`${dir}/acl.applied`, 'x\n', ctl.constants.O_TRUNC), { code: 'ELOOP' });
		assert.throws(() => ctl.writeOwned(`${dir}/audit.log`, 'x\n', ctl.constants.O_APPEND), { code: 'ELOOP' });
		assert.throws(() => ctl.readOwned(`${dir}/.sync-primary`, 'utf8'), { code: 'ELOOP' });
		assert.equal(fs.readFileSync(victim, 'utf8'), 'secret\n');

		fs.linkSync(victim, `${dir}/hard`);
		assert.throws(() => ctl.writeOwned(`${dir}/hard`, 'x\n', ctl.constants.O_TRUNC), /not a regular file/);
		assert.equal(fs.readFileSync(victim, 'utf8'), 'secret\n', 'not truncated before the check');

		assert.equal(spawnSync('mkfifo', [`${dir}/fifo`]).status, 0);
		assert.throws(() => ctl.readOwned(`${dir}/fifo`, 'utf8'), /not a regular file/);
		assert.throws(() => ctl.writeOwned(`${dir}/fifo`, 'x\n', ctl.constants.O_APPEND), { code: 'ENXIO' });

		ctl.writeOwned(`${dir}/plain`, 'a\n', ctl.constants.O_APPEND);
		ctl.writeOwned(`${dir}/plain`, 'b\n', ctl.constants.O_APPEND);
		assert.equal(fs.readFileSync(`${dir}/plain`, 'utf8'), 'a\nb\n');
		ctl.writeAtomic(`${dir}/devices.conf`, 'one\n');
		assert.equal(fs.readFileSync(`${dir}/devices.conf`, 'utf8'), 'one\n');
		assert.equal(fs.statSync(`${dir}/devices.conf`).mode & 0o777, 0o600);
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
});
