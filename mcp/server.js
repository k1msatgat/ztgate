#!/usr/bin/env node
/* ztgate MCP 서버 (stdio).
 *
 * AI 클라이언트가 ssh 로 이 프로그램을 띄우고 stdin/stdout 으로 MCP 를 말한다.
 * 여기에는 권한도 로직도 없다. 도구의 입력 형식을 선언하고, 요청을 그대로 root 헬퍼 둘
 * (ztgate_ctl, 배포기 ztgate-deploy) 가운데 하나에 넘기고, 답을 돌려줄 뿐이다. 검증과 실제 동작은
 * ctl.cjs 와 deploy.cjs 에 있다.
 *
 * stdout 은 프로토콜 전용이다. 사람이 볼 메시지는 stderr 로만 보낸다. */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const CTL_TIMEOUT_MS = 200000;	/* auth_check 가 가장 길다 */
const DEPLOY = '/opt/ztgate-mcp/libexec/ztgate-deploy';

/* 패키지의 자리. 예전 mcp/install.sh 로 서버를 깐 장비는 패키지로 옮기기 전까지 /usr/local/sbin 이다.
 * 옮기는 동안에도 이 프로세스는 떠 있으므로 부를 때마다 본다. */
function ctlPath() {
	return existsSync('/usr/sbin/ztgate_ctl') ? '/usr/sbin/ztgate_ctl' : '/usr/local/sbin/ztgate_ctl';
}

function helper(path, request, timeoutMs) {
	const root = process.getuid() === 0;
	const name = path.split('/').pop();
	const child = spawn(root ? path : 'sudo', root ? [] : ['-n', path], {
		stdio: ['pipe', 'pipe', 'pipe'],
		timeout: timeoutMs,
	});

	return new Promise((resolve) => {
		let out = '';
		let err = '';

		child.stdout.on('data', (d) => { out += d; });
		child.stderr.on('data', (d) => { err += d; });
		child.on('error', (e) => resolve({ ok: false, error: `cannot run ${name}: ${e.message}` }));
		child.on('close', () => {
			try {
				resolve(JSON.parse(out));
			} catch (e) {
				resolve({ ok: false, error: `${name} gave no answer: ${err.trim() || 'no output'}` });
			}
		});
		child.stdin.end(JSON.stringify(request));
	});
}

async function call(cmd, args = {}) {
	return answer(await helper(ctlPath(), { cmd, ...args, actor: 'mcp' }, CTL_TIMEOUT_MS));
}

/* deploy 와 deploy_rollback 은 작업을 적고 바로 답한다. deploy_status 는 wait_seconds 만큼 기다린 뒤 답한다. */
async function deploy(cmd, args = {}) {
	return answer(await helper(DEPLOY, { cmd, ...args, actor: 'mcp' }, ((args.wait_seconds ?? 0) + 30) * 1000));
}

function answer(reply) {
	const { ok, error, ...result } = reply;

	if (!ok) {
		return { isError: true, content: [{ type: 'text', text: error }] };
	}

	return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
}

const requirements = z.object({
	firewall: z.boolean().optional().describe('Windows Firewall must be on'),
	antivirus: z.boolean().optional().describe('Windows Security Center must report a healthy antivirus'),
	disk: z.boolean().optional().describe('the system disk must be encrypted (BitLocker protection on, or / on dm-crypt on Linux)'),
	min_build: z.number().int().min(0).optional().describe('minimum OS build (Windows 11 starts at 22000); 0 = no check'),
}).strict().describe('Posture the device must report at handshake and at every keepalive. Omitted items are not checked. A value the client reports as "unknown" never passes.');

const tags = z.array(z.string().regex(/^[a-z0-9_-]{1,32}$/)).max(4).describe('device tags (roles), e.g. ["eng", "laptop"]: ACL rules with tags apply only to devices that carry one of them');
const deviceId = z.string().regex(/^[0-9a-fA-F]{32}$/).describe('device id, 32 hex digits (from device_list)');
const label = z.string().max(32).describe('human-readable name, e.g. "woo-laptop"');
const tunnelIp = z.string().describe('tunnel IPv4 address assigned to this device, e.g. 10.0.0.3. The server pushes it to the device; nothing is typed on the client');

const READ = { readOnlyHint: true, openWorldHint: false };
const WRITE = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };
const DISRUPT = { readOnlyHint: false, destructiveHint: true, openWorldHint: false };

const server = new McpServer({ name: 'ztgate', version: '0.1.0' }, {
	instructions: [
		'Controls the ztgate server (a UDP/TUN VPN with device authentication and posture checks) on this Linux host.',
		'Clients are separate Windows machines and are not controlled from here; a client is cut off or admitted by changing its entry in the device list.',
		'Device changes (device_add / device_update / device_remove) and ACL rule changes apply to the running server immediately without dropping sessions. Only turning the ACL on for the first time or off (acl_clear) needs server_restart; restart_required tells you when.',
		'Call server_status first: it shows whether the server is up, who is connected and why a device was recently rejected.',
		'To change the server software use deploy; it puts the previous package back by itself when the new server fails its checks.',
	].join(' '),
});

/* ---- 서버 ------------------------------------------------------------------ */

server.registerTool('server_status', {
	description: 'Show whether the VPN server is running, its listen port and tunnel interface, the current sessions as the server itself reports them (device, endpoint, last reported posture, seconds since last packet, packet/byte counts, ACL denials), counters of handshakes and rejections by reason, the last few rejection log lines, and whether an ACL change is waiting for a restart.',
	inputSchema: {},
	annotations: READ,
}, () => call('status'));

server.registerTool('server_start', {
	description: 'Start the VPN server and bring its tunnel interface up. No-op if it is already running.',
	inputSchema: {},
	annotations: WRITE,
}, () => call('start'));

server.registerTool('server_stop', {
	description: 'Stop the VPN server. Every client loses its tunnel until the server is started again.',
	inputSchema: {},
	annotations: DISRUPT,
}, () => call('stop'));

server.registerTool('server_restart', {
	description: 'Restart the VPN server. All sessions are dropped; clients re-handshake on their own within about 30 seconds. Needed only to turn the ACL on or off.',
	inputSchema: {},
	annotations: DISRUPT,
}, () => call('restart'));

server.registerTool('server_reload', {
	description: 'Make the running server re-read the device list and the ACL (SIGHUP) without dropping sessions. The device_* and acl_set tools already do this; use it only after a file was edited by hand.',
	inputSchema: {},
	annotations: WRITE,
}, () => call('reload'));

server.registerTool('server_logs', {
	description: 'Read the server log, oldest first. Lines look like "[HS] device <id> authenticated as <ip>", "[ka] device <id> posture rejected", "[peer] register/drop/expire", "[deny] <src> -> <dst>" (ACL), "[udp->tun]" / "[tun->udp]" (one per data packet).',
	inputSchema: {
		lines: z.number().int().min(1).max(500).optional().describe('how many lines to return (default 50)'),
		contains: z.string().max(100).optional().describe('only lines containing this exact text, e.g. "[HS]" or a device id'),
		since_seconds: z.number().int().min(1).max(604800).optional().describe('only lines from the last N seconds'),
	},
	annotations: READ,
}, (a) => call('logs', a));

server.registerTool('audit_log', {
	description: 'Read the audit log, oldest first: one JSON event per thing that happened. session_open (device, tunnel ip, endpoint, posture), session_close (reason: expired / posture / device_removed / replaced / evicted / closed (the client said it was leaving) / shutdown (the server stopped) / rekey (the session key reached its lifetime and the client was asked to re-handshake), with packet and byte counts), auth_denied (reason: unknown_device / bad_auth / posture), access (the first packet a session sends to each destination: dst, proto, dport, allow or deny and why), reload, enrolled (a device registered itself with an enrollment code), login / logout (a user token on a session), admin (a change made through this MCP, the web console or ztgate_ctl: who, which command, ok or the error), deploy (the end of a deploy or rollback job: outcome, from and to commit). Use it to answer "who connected, what did they reach, why were they refused, who changed what". Unlike server_logs it is per event rather than per packet and it survives server restarts.',
	inputSchema: {
		lines: z.number().int().min(1).max(500).optional().describe('how many events to return (default 50)'),
		event: z.enum(['session_open', 'session_close', 'auth_denied', 'access', 'reload', 'enrolled', 'login', 'logout', 'admin', 'deploy']).optional().describe('only this kind of event'),
		device: deviceId.optional().describe('only events of this device (32 hex digits)'),
		since_seconds: z.number().int().min(1).max(2592000).optional().describe('only events from the last N seconds'),
	},
	annotations: READ,
}, (a) => call('audit', a));

/* ---- 기기 ------------------------------------------------------------------ */

server.registerTool('device_list', {
	description: 'List registered devices: id, label, tunnel IP and posture requirements. Keys are never returned.',
	inputSchema: {},
	annotations: READ,
}, () => call('device_list'));

server.registerTool('device_add', {
	description: 'Register a device by hand from an id and key printed on the device ("vpn_client.exe enroll" without a code). Prefer enroll_create, which avoids copying the key. Applied to the running server immediately.',
	inputSchema: {
		id: deviceId.describe('device id, 32 hex digits, as printed by enroll'),
		key: z.string().regex(/^([0-9a-fA-F]{64}|p256:[0-9a-fA-F]{128})$/).describe('a shared device key, 64 hex digits, as printed by "enroll" without a code; or p256:<128 hex digits>, a device public key (the server then holds no secret for this device and needs its server key, -k)'),
		tunnel_ip: tunnelIp,
		requirements: requirements.optional(),
		tags: tags.optional(),
		label: label.optional(),
	},
	annotations: WRITE,
}, (a) => call('device_add', a));

server.registerTool('enroll_create', {
	description: 'Create a one-time enrollment code for a new device. This is the normal way to add a device: hand the code to the person at the device, they type it into the client ("vpn_client.exe enroll <server> <port> <code>" or the GUI), and the device registers its own id and key over an encrypted session, so no key is ever copied by hand. The code works once and expires. The tunnel IP, posture requirements and label you set here are what the device gets. The code is returned only in this answer. When server.env has PUBLIC_ADDRESS the answer also carries an "invite" link (ztgate://enroll?...) that does the same in one click on Windows; it contains the code, so treat it as secret.',
	inputSchema: {
		label: label.optional(),
		tunnel_ip: tunnelIp.optional().describe('tunnel IPv4 address for the device; omit to take the lowest free address in the tunnel subnet'),
		requirements: requirements.optional(),
		tags: tags.optional(),
		connector: z.array(z.string()).max(4).optional().describe('make this device an app connector for these networks, e.g. ["10.101.0.0/16"]: a machine inside that network that runs "vpn_client connector <server-ip> <port> <lan-ifname>". The server then relays packets for those networks (after the ACL) into the connector\'s session instead of its own tun, so the protected network needs no inbound port. Clients keep getting the routes from the ACL; the connector gets none.'),
		ttl_minutes: z.number().int().min(1).max(1440).optional().describe('how long the code stays valid (default 15)'),
	},
	annotations: WRITE,
}, (a) => call('enroll_create', a));

server.registerTool('enroll_list', {
	description: 'List enrollment codes that were created and not yet used or expired: id (a handle for enroll_revoke, not the code), label, reserved tunnel IP, requirements and seconds left. The codes themselves cannot be read back.',
	inputSchema: {},
	annotations: READ,
}, () => call('enroll_list'));

server.registerTool('enroll_revoke', {
	description: 'Cancel a pending enrollment code before it is used, e.g. when it was sent to the wrong person.',
	inputSchema: { id: deviceId.describe('id of the pending enrollment, from enroll_list') },
	annotations: WRITE,
}, (a) => call('enroll_revoke', a));

server.registerTool('device_update', {
	description: 'Change a device\'s posture requirements, tunnel IP or label. "requirements" replaces the whole set. Applied immediately: a connected device that no longer meets the policy is dropped at its next keepalive (within 10s).',
	inputSchema: {
		id: deviceId,
		requirements: requirements.optional(),
		tags: tags.optional(),
		tunnel_ip: tunnelIp.optional(),
		label: label.optional(),
	},
	annotations: DISRUPT,
}, (a) => call('device_update', a));

server.registerTool('device_remove', {
	description: 'Revoke a device. Its key is deleted and cannot be read back; a connected session is dropped at its next keepalive (within 10s). Re-admitting it requires enrolling again.',
	inputSchema: { id: deviceId },
	annotations: DISRUPT,
}, (a) => call('device_remove', a));

/* ---- ACL ------------------------------------------------------------------- */

server.registerTool('acl_get', {
	description: 'Show the ACL rules for packets coming out of the tunnel (client -> server) and whether the running server still uses an older version (restart_required).',
	inputSchema: {},
	annotations: READ,
}, () => call('acl_get'));

server.registerTool('acl_set', {
	description: 'Replace the whole ACL: which destinations an admitted device may reach, optionally with a stricter posture per destination than the device needs to connect. The allowed destination ranges are also what each device is told to route into the tunnel (ranges inside the tunnel subnet and "any" are not pushed), so a rule for 10.20.0.0/16 both permits and routes it; connected devices pick up route changes within 10s. Rules are checked top to bottom, the first match wins, and a packet matching no rule is denied. Applied from the next packet if the server is already running with an ACL; if it was started without one, restart_required comes back true and server_restart turns it on.',
	inputSchema: {
		rules: z.array(z.object({
			src: z.string().describe('a.b.c.d, a.b.c.d/n or "any"'),
			dst: z.string().describe('a.b.c.d, a.b.c.d/n or "any"'),
			proto: z.string().describe('"icmp", "tcp", "udp", "any" or a protocol number'),
			dport: z.string().optional().describe('"n", "lo-hi" or "any" (tcp/udp only; default "any")'),
			action: z.enum(['allow', 'deny']),
			require: requirements.optional().describe('allow rules only: posture a session must currently report to be allowed by this rule, e.g. SSH only from devices with the firewall on. If the rule matches but the posture falls short the packet is denied; later rules are not tried.'),
			users: z.object({
				users: z.array(z.string()).optional().describe('user names as the identity provider reports them (the server\'s user-claim)'),
				groups: z.array(z.string()).optional().describe('group names from the token\'s groups claim'),
			}).strict().optional().describe('allow rules only: who must be logged in on the session (a user token sent by the client, see README "user login"). Any one listed user or group is enough; at most 4 in total. A session with nobody logged in, or whose token has expired, does not match and the packet is denied; later rules are not tried. Rules without users keep working on the device alone.'),
			tags: tags.optional().describe('which devices this rule is for, like src but by role: the rule applies only to a device carrying one of these tags; for other devices the rule is skipped and later rules are tried. Allowed on allow and deny rules.'),
		}).strict()).min(1).max(1024),
	},
	annotations: DISRUPT,
}, (a) => call('acl_set', a));

server.registerTool('acl_clear', {
	description: 'Turn the ACL off (every packet from an authenticated session is accepted). Takes effect only after server_restart.',
	inputSchema: {},
	annotations: DISRUPT,
}, () => call('acl_clear'));

/* ---- 검사 ------------------------------------------------------------------ */

server.registerTool('auth_check', {
	description: 'Run the protocol-level self test of device authentication, posture checks and continuous verification against a temporary server instance (about a minute). The VPN server must be stopped first.',
	inputSchema: {},
	annotations: WRITE,
}, () => call('auth_check'));

/* ---- 배포 ------------------------------------------------------------------ */

const accept = z.array(z.enum(['protocol_break', 'no_revert'])).max(2).optional()
	.describe('risks you accept, otherwise the job refuses them: protocol_break = the target accepts no client protocol version that the running server accepts, so every connected client is cut off (docs/decisions/0012-version-compat.md); no_revert = the installed server was not installed by this deployer (or nothing is installed), so a failed check cannot be undone automatically');
const jobId = z.string().regex(/^d-\d{8}T\d{6}Z-[0-9a-f]{4}$/).describe('job id from deploy or deploy_rollback');

server.registerTool('deploy', {
	description: 'Build the given ref of the ztgate server from the git remote configured on this host into a package, install it, and check that the new server comes back healthy (service steady for 15s without restarts, the running binary is the one from the package, ztgate_ctl status works, it answers on its UDP port, the server key is unchanged); if the check fails, the previously installed package is reinstalled and checked automatically. Returns a job at once; the whole job (fetch, build, install, a 15 second check, and a revert with a second check if needed) takes from under a minute to a few minutes on a small host, so follow it with deploy_status(job, wait_seconds: 150) until outcome is set. Outcomes: installed; unchanged (that commit was already installed: nothing happened); failed (stopped before the install, or the package manager refused it: nothing changed; see error and log_tail); reverted (the target failed its check and the previous package is back and healthy); broken (needs a human: see note); interrupted (the job died, e.g. a reboot; it is not undone by itself). A commit built before is reused without rebuilding. Sessions drop once when the server restarts and clients reconnect within about 30 seconds. A stopped server stays stopped. Only branches and tags allowed in /etc/ztgate-deploy/deploy.conf can be deployed; a commit id must be reachable from one of them. One job runs at a time.',
	inputSchema: {
		ref: z.string().min(1).max(100).describe('branch, tag or commit id (7-40 hex) on the configured remote, e.g. "main", "fix/icmp-frag", "v0.9.4", "9272113"'),
		accept,
	},
	annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
}, (a) => deploy('deploy', a));

server.registerTool('deploy_status', {
	description: 'Show the installed server package (commit, version), the one before it (what deploy_rollback goes back to), the kept packages, the allowed remote, branches and tags, and a deploy job: phase (queued, fetching, building, backing_up, installing, checking, reverting, done), outcome (null while it runs), the time spent per phase, the health check (and the check after a revert), the backup taken before the install, and the log tail while it builds or after a failure. Without job: the running job, or else the latest one. wait_seconds blocks until that job has an outcome or the time runs out.',
	inputSchema: {
		job: jobId.optional(),
		wait_seconds: z.number().int().min(0).max(150).optional().describe('wait up to this many seconds for the job to finish (default 0)'),
	},
	annotations: READ,
}, (a) => deploy('deploy_status', a));

server.registerTool('deploy_rollback', {
	description: 'Reinstall a kept package: by default the one installed before the current one, or the kept package of the given commit. It is a job like deploy (backup, install, the same health check, and back to the current package if the check fails), without fetching or building, so it usually ends within one deploy_status(job, wait_seconds: 60).',
	inputSchema: {
		to: z.string().regex(/^[0-9a-f]{7,40}$/).optional().describe('commit of a kept package (deploy_status lists them); default: the previous one'),
		accept,
	},
	annotations: DISRUPT,
}, (a) => deploy('deploy_rollback', a));

await server.connect(new StdioServerTransport());
