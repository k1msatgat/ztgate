/* MCP 서버(server.js)가 선언한 것과 root 헬퍼 둘이 받는 것이 같은지: node --test mcp/surface.test.cjs
 * server.js 는 띄우면 stdio 를 붙잡으므로 읽기만 한다. */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ctl = require('./ctl.cjs');
const deploy = require('./deploy.cjs');

const server = fs.readFileSync(`${__dirname}/server.js`, 'utf8');

test('audit_log takes exactly the events ztgate_ctl filters on', () => {
	const m = /event: z\.enum\(\[([^\]]*)\]\)/.exec(server);

	assert.ok(m, 'audit_log has an event enum');
	assert.deepEqual(JSON.parse(`[${m[1].replace(/'/g, '"')}]`), ctl.AUDIT_EVENTS);
});

test('every command a tool sends exists in the helper it goes to', () => {
	const calls = [...server.matchAll(/\bcall\('([a-z_]+)'/g)].map((x) => x[1]);
	const deploys = [...server.matchAll(/\bdeploy\('([a-z_]+)'/g)].map((x) => x[1]);

	assert.ok(calls.length > 10);
	for (const c of calls) {
		assert.ok(Object.hasOwn(ctl.COMMANDS, c), `ztgate_ctl has no command ${c}`);
	}
	assert.deepEqual(deploys.sort(), [...deploy.REQUESTS].sort());
});
