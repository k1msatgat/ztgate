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
