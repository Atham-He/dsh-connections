/**
 * Plain-node unit tests for `lib/ssh-config.js` and `lib/connections.js`.
 *
 * No dependencies and no network: the parser is exercised against fixtures and
 * the real `~/.ssh/config` (read-only), and ConnectionManager runs against a
 * fake Host `subprocess` service. Real ssh is never spawned, and no remote
 * host is contacted.
 *
 * Run: node plugins/dsh-connections/test/unit.test.mjs
 */

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';

import {
  describeHost,
  expandHome,
  loadSshConfig,
  parseDestination,
  parseSshConfig,
} from '../lib/ssh-config.js';
import { ConnectionManager } from '../lib/connections.js';

let passed = 0;
let failed = 0;

/**
 * @param {string} name
 * @param {() => unknown | Promise<unknown>} fn
 */
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL - ${name}`);
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  }
}

/** @param {string} text */
function reader(text) {
  return {
    text,
    lossy: false,
    readFrom(offset) {
      const from = Math.min(Math.max(0, Number(offset) || 0), this.text.length);
      return { text: this.text.slice(from), nextOffset: this.text.length, lossy: this.lossy };
    },
  };
}

/**
 * Fake Host subprocess service. `spawn` delegates to the supplied behaviour so
 * each test can shape the child handle it needs.
 */
class FakeSubprocess {
  /**
   * @param {{ failResolve?: boolean, failScp?: boolean, onSpawn: (spec: any, index: number) => any }} options
   */
  constructor(options) {
    this.failResolve = options.failResolve === true;
    this.failScp = options.failScp === true;
    this.onSpawn = options.onSpawn;
    this.spawns = [];
  }

  async resolveExecutable(name) {
    if (this.failResolve) throw new Error('not found');
    if (this.failScp && name !== 'ssh') throw new Error('not found');
    return `C:/fake/bin/${name}.exe`;
  }

  spawn(spec) {
    this.spawns.push(spec);
    return this.onSpawn(spec, this.spawns.length);
  }
}

/** @param {{ stdout?: string, stderr?: string, done?: Promise<any>, stdin?: any }} options */
function fakeHandle(options = {}) {
  const stdout = reader(options.stdout ?? '');
  const stderr = reader(options.stderr ?? '');
  const handle = {
    stdin: options.stdin,
    stdout: undefined,
    stderr: undefined,
    control: undefined,
    collected: { stdout, stderr },
    done: options.done ?? new Promise(() => {}),
    terminated: false,
    terminate() {
      handle.terminated = true;
    },
    async waitForExit() {
      return true;
    },
  };
  return handle;
}

// ---------------------------------------------------------------------------
// expandHome
// ---------------------------------------------------------------------------

await test('expandHome expands ~, ~/ and ~\\ but not ~user', () => {
  assert.equal(expandHome('~', 'C:\\Users\\me'), 'C:\\Users\\me');
  assert.equal(expandHome('~/.ssh/id_ed25519', 'C:\\Users\\me'), 'C:\\Users\\me\\.ssh\\id_ed25519');
  assert.equal(expandHome('~\\.ssh\\id_ed25519', 'C:\\Users\\me'), 'C:\\Users\\me\\.ssh\\id_ed25519');
  assert.equal(expandHome('~/.ssh/id_ed25519', '/home/me'), '/home/me/.ssh/id_ed25519');
  assert.equal(expandHome('~postgres/key', 'C:\\Users\\me'), '~postgres/key');
  assert.equal(expandHome('relative/key', 'C:\\Users\\me'), 'relative/key');
});

// ---------------------------------------------------------------------------
// parseSshConfig
// ---------------------------------------------------------------------------

await test('parseSshConfig reads Host blocks, aliases, quoted values and comments', () => {
  const fixture = [
    '# leading comment',
    'Host alpha beta',
    '    HostName example.com',
    '    User bob',
    '    Port 2200',
    '    IdentityFile "~/.ssh/id_ed25519"',
    '    ProxyJump jump@bastion:22',
    '    ServerAliveInterval 30   # unrelated option',
    '',
    'host gamma',
    '    hostname "gamma.example.com"',
    '    USER "carol"',
    '    identityfile ~/.ssh/key2',
    '    # trailing comment',
  ].join('\r\n');

  const { hosts, warnings } = parseSshConfig(fixture, { home: 'C:\\Users\\me' });
  assert.deepEqual(warnings, []);
  assert.equal(hosts.length, 3);
  assert.deepEqual(hosts.map((host) => host.alias), ['alpha', 'beta', 'gamma']);

  const alpha = hosts[0];
  assert.equal(alpha.source, 'ssh-config');
  assert.equal(alpha.hostName, 'example.com');
  assert.equal(alpha.user, 'bob');
  assert.equal(alpha.port, 2200);
  assert.equal(alpha.identityFile, 'C:\\Users\\me\\.ssh\\id_ed25519');
  assert.equal(alpha.proxyJump, 'jump@bastion:22');
  assert.deepEqual(hosts[1], { ...alpha, alias: 'beta' });

  const gamma = hosts[2];
  assert.equal(gamma.hostName, 'gamma.example.com');
  assert.equal(gamma.user, 'carol');
  assert.equal(gamma.identityFile, 'C:\\Users\\me\\.ssh\\key2');
  assert.equal(gamma.port, undefined);
});

await test('parseSshConfig ignores wildcard/pattern aliases with one warning each', () => {
  const fixture = [
    'Host *.corp.example.com',
    '    User wild',
    'Host concrete *.other',
    '    HostName real.example.com',
    'Host !negated',
    '    User no',
  ].join('\n');
  const { hosts, warnings } = parseSshConfig(fixture);
  assert.deepEqual(hosts.map((host) => host.alias), ['concrete']);
  assert.equal(hosts[0].hostName, 'real.example.com');
  assert.equal(warnings.length, 3);
  assert.match(warnings[0], /\*\.corp\.example\.com/);
  assert.match(warnings[1], /\*\.other/);
  assert.match(warnings[2], /!negated/);
});

await test('parseSshConfig warns on invalid ports and ignores Match bodies', () => {
  const fixture = [
    'Host weird',
    '    Port 99999',
    '    User ok',
    'Match host internal',
    '    User ignored',
    'Host fine',
    '    Port 22',
  ].join('\n');
  const { hosts, warnings } = parseSshConfig(fixture);
  const weird = hosts.find((host) => host.alias === 'weird');
  assert.equal(weird.port, undefined);
  assert.equal(weird.user, 'ok');
  assert.match(warnings.join('\n'), /invalid Port "99999"/);
  assert.match(warnings.join('\n'), /Match/);
  assert.equal(hosts.find((host) => host.alias === 'fine').port, 22);
});

await test('parseSshConfig merges duplicate aliases first-value-wins', () => {
  const { hosts } = parseSshConfig(
    ['Host dup', '    User alice', 'Host dup', '    User bob', '    Port 2222'].join('\n'),
  );
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].user, 'alice');
  assert.equal(hosts[0].port, 2222);
});

// ---------------------------------------------------------------------------
// loadSshConfig
// ---------------------------------------------------------------------------

await test('loadSshConfig returns exists:false for a missing file without throwing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-connections-test-'));
  try {
    const missing = await loadSshConfig({ configPath: join(dir, 'nope', 'config') });
    assert.equal(missing.exists, false);
    assert.equal(missing.path, join(dir, 'nope', 'config'));
    assert.deepEqual(missing.hosts, []);
    assert.deepEqual(missing.warnings, []);

    const configPath = join(dir, 'config');
    await writeFile(configPath, 'Host temp\n    HostName 10.0.0.1\n    User u\n', 'utf8');
    const loaded = await loadSshConfig({ configPath, home: dir });
    assert.equal(loaded.exists, true);
    assert.equal(loaded.hosts.length, 1);
    assert.equal(loaded.hosts[0].hostName, '10.0.0.1');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('loadSshConfig parses the real ~/.ssh/config read-only', async () => {
  const home = homedir();
  const loaded = await loadSshConfig({ home });
  if (!loaded.exists) {
    console.log('    (skipped: no ~/.ssh/config on this machine)');
    return;
  }
  const aliases = loaded.hosts.map((host) => host.alias);
  for (const expected of ['hpc2021.hku.hk', 'hpc2021-batch', 'hzyhkucivil', '64.176.207.154']) {
    assert.ok(aliases.includes(expected), `missing host ${expected} in ${loaded.path}`);
  }
  const hpc = loaded.hosts.find((host) => host.alias === 'hpc2021.hku.hk');
  assert.equal(hpc.hostName, 'hpc2021.hku.hk');
  assert.equal(hpc.user, 'u3011959');
  assert.match(hpc.identityFile ?? '', /\.ssh[\\/]id_ed25519$/);
  assert.equal(hpc.source, 'ssh-config');

  const civil = loaded.hosts.find((host) => host.alias === 'hzyhkucivil');
  assert.equal(civil.hostName, '60.31.21.42');
  assert.equal(civil.port, 19998);

  const vps = loaded.hosts.find((host) => host.alias === '64.176.207.154');
  assert.equal(vps.user, 'root');

  assert.equal(
    loaded.warnings.filter((warning) => /wildcard/i.test(warning)).length,
    0,
    `unexpected wildcard warnings: ${loaded.warnings.join(' | ')}`,
  );
});

// ---------------------------------------------------------------------------
// parseDestination
// ---------------------------------------------------------------------------

await test('parseDestination handles alias, user, port and user@host:port forms', () => {
  assert.deepEqual(parseDestination('hpc2021-batch'), {
    destination: 'hpc2021-batch',
    host: 'hpc2021-batch',
    sshArgs: [],
  });
  assert.deepEqual(parseDestination(' alice@devbox '), {
    destination: 'alice@devbox',
    host: 'devbox',
    user: 'alice',
    sshArgs: [],
  });
  assert.deepEqual(parseDestination('devbox:2222'), {
    destination: 'devbox:2222',
    host: 'devbox',
    port: 2222,
    sshArgs: ['-p', '2222'],
  });
  assert.deepEqual(parseDestination('alice@devbox:22'), {
    destination: 'alice@devbox:22',
    host: 'devbox',
    user: 'alice',
    port: 22,
    sshArgs: ['-p', '22'],
  });
  assert.deepEqual(parseDestination('[::1]:2222'), {
    destination: '[::1]:2222',
    host: '::1',
    port: 2222,
    sshArgs: ['-p', '2222'],
  });
});

await test('parseDestination rejects empty, malformed and out-of-range input', () => {
  for (const value of ['', '   ', 'devbox:0', 'devbox:65536', 'devbox:abc', 'a@b@c', '@host', 'user@', '-oProxyCommand=evil', 'a b']) {
    assert.throws(() => parseDestination(value), Error, `expected rejection for ${JSON.stringify(value)}`);
  }
  assert.throws(() => parseDestination('::1:22'), /IPv6/);
  assert.throws(() => parseDestination(42), /string/);
});

// ---------------------------------------------------------------------------
// describeHost
// ---------------------------------------------------------------------------

await test('describeHost omits defaults and unknown parts', () => {
  assert.equal(describeHost({ hostName: 'example.com', user: 'bob' }), 'bob@example.com');
  assert.equal(describeHost({ hostName: 'example.com', user: 'bob', port: 22 }), 'bob@example.com');
  assert.equal(describeHost({ hostName: 'example.com', user: 'bob', port: 2200 }), 'bob@example.com:2200');
  assert.equal(describeHost({ host: 'devbox', port: 2222 }), 'devbox:2222');
  assert.equal(describeHost({ alias: 'only-alias' }), 'only-alias');
  assert.equal(describeHost(null), '');
});

// ---------------------------------------------------------------------------
// ConnectionManager with a fake subprocess service
// ---------------------------------------------------------------------------

await test('ConnectionManager requires a subprocess service', () => {
  assert.throws(() => new ConnectionManager({}), /subprocess/);
  assert.throws(() => new ConnectionManager({ subprocess: {} }), /spawn/);
});

await test('init throws a readable error when ssh cannot be resolved', async () => {
  const manager = new ConnectionManager({ subprocess: new FakeSubprocess({ failResolve: true }) });
  await assert.rejects(() => manager.init(), /OpenSSH client \(ssh\) is not available/);
  await manager.dispose();
});

await test('listHosts reads the configured home', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-connections-home-'));
  try {
    const manager = new ConnectionManager({
      subprocess: new FakeSubprocess({ onSpawn: () => fakeHandle() }),
      home: dir,
    });
    const result = await manager.listHosts();
    assert.equal(result.exists, false);
    assert.deepEqual(result.hosts, []);
    assert.equal(result.path, join(dir, '.ssh', 'config'));
    await manager.dispose();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

await test('exec resolves for a non-zero exit and reports captured output', async () => {
  const subprocess = new FakeSubprocess({
    onSpawn: () => fakeHandle({
      stdout: 'hello\n',
      stderr: 'boom\n',
      done: Promise.resolve({ exitCode: 3, signal: null }),
    }),
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home', execTimeoutMs: 5000 });
  const result = await manager.exec({ host: 'alice@example.com:2222', command: 'echo hi' });

  assert.equal(result.host, 'alice@example.com:2222');
  assert.equal(result.command, 'echo hi');
  assert.equal(result.exitCode, 3);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, 'hello\n');
  assert.equal(result.stderr, 'boom\n');
  assert.equal(result.truncated, false);
  assert.equal(result.timedOut, false);
  assert.ok(result.durationMs >= 0);

  const argv = subprocess.spawns[0].argv;
  assert.equal(argv[0], 'C:/fake/bin/ssh.exe');
  assert.equal(argv[1], '-T');
  assert.ok(argv.includes('BatchMode=yes'));
  assert.ok(!argv.includes('StrictHostKeyChecking=no'));
  assert.deepEqual(argv.slice(-4, -1), ['-p', '2222', 'alice@example.com']);
  assert.equal(argv.at(-1), 'echo hi');
  assert.equal(subprocess.spawns[0].cwd, 'C:\\home');
  await manager.dispose();
});

await test('exec marks a timeout instead of throwing', async () => {
  const subprocess = new FakeSubprocess({
    onSpawn: (spec) => {
      const done = new Promise((resolve) => {
        spec.signal?.addEventListener('abort', () => resolve({ exitCode: null, signal: 'SIGTERM' }), { once: true });
      });
      return fakeHandle({ stdout: 'partial output', done });
    },
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home', execTimeoutMs: 5000 });
  const result = await manager.exec({ host: 'devbox', command: 'sleep 60', timeoutMs: 60 });
  assert.equal(result.timedOut, true);
  assert.equal(result.signal, 'SIGTERM');
  assert.equal(result.stdout, 'partial output');
  assert.equal(result.exitCode, null);
  await manager.dispose();
});

await test('copy builds an upload scp argv with -P for explicit ports', async () => {
  const subprocess = new FakeSubprocess({
    onSpawn: () => fakeHandle({ done: Promise.resolve({ exitCode: 0, signal: null }) }),
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home', execTimeoutMs: 5000 });
  const result = await manager.copy({
    host: 'alice@example.com:2222',
    direction: 'upload',
    localPath: 'C:\\tmp\\a.txt',
    remotePath: '~/a.txt',
    recursive: true,
  });
  assert.equal(result.ok, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.direction, 'upload');
  const argv = subprocess.spawns[0].argv;
  assert.equal(argv[0], 'C:/fake/bin/scp.exe');
  assert.ok(argv.includes('-r'));
  assert.deepEqual(argv.slice(-4, -2), ['-P', '2222']);
  assert.equal(argv.at(-2), 'C:\\tmp\\a.txt');
  assert.equal(argv.at(-1), 'alice@example.com:~/a.txt');
  assert.ok(!argv.includes('StrictHostKeyChecking=no'));
  await manager.dispose();
});

await test('copy reports a missing scp executable', async () => {
  const subprocess = new FakeSubprocess({ failScp: true, onSpawn: () => fakeHandle() });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  await assert.rejects(
    () => manager.copy({ host: 'devbox', direction: 'upload', localPath: 'a', remotePath: 'b' }),
    /scp was not found/,
  );
  await manager.dispose();
});

await test('open/send/read/close drive an interactive session', async () => {
  const writes = [];
  const subprocess = new FakeSubprocess({
    onSpawn: () => {
      const stdout = reader('banner\n$ ');
      const stderr = reader('');
      const { promise: done, resolve: resolveDone } = Promise.withResolvers();
      const stdin = new Writable({
        write(chunk, encoding, callback) {
          const text = chunk.toString();
          writes.push(text);
          if (text.startsWith('ls')) stdout.text += 'file.txt\n$ ';
          if (text.startsWith('exit')) resolveDone({ exitCode: 0, signal: null });
          callback();
        },
      });
      const handle = fakeHandle({ stdin, done });
      handle.collected.stdout = stdout;
      handle.collected.stderr = stderr;
      return handle;
    },
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  const opened = await manager.open({ host: 'hpc2021-batch', name: ' batch box ' });
  assert.equal(opened.sessionId, 'ssh-1');
  assert.equal(opened.host, 'hpc2021-batch');
  assert.equal(opened.pid, 0);
  assert.equal(opened.status, 'running');
  assert.match(opened.initialOutput, /banner/);

  const argv = subprocess.spawns[0].argv;
  assert.equal(argv[0], 'C:/fake/bin/ssh.exe');
  assert.equal(argv[1], '-tt');
  assert.equal(argv.at(-1), 'hpc2021-batch');
  assert.ok(argv.includes('BatchMode=yes'));

  const sent = await manager.send({ sessionId: 'ssh-1', text: 'ls', waitMs: 20 });
  assert.equal(sent.status, 'running');
  assert.equal(sent.output, 'file.txt\n$ ');
  assert.equal(sent.exitCode, null);
  assert.equal(writes[0], 'ls\r');

  assert.equal(manager.read({ sessionId: 'ssh-1' }).output, '');
  assert.deepEqual(manager.sessions(), [
    {
      sessionId: 'ssh-1',
      host: 'hpc2021-batch',
      pid: 0,
      status: 'running',
      exitCode: null,
      name: 'batch box',
    },
  ]);

  const closed = await manager.close({ sessionId: 'ssh-1' });
  assert.equal(closed.closed, true);
  assert.equal(closed.exitCode, 0);
  assert.equal(manager.sessions().length, 0);
  assert.deepEqual(await manager.close({ sessionId: 'ssh-1' }), { sessionId: 'ssh-1', closed: true, exitCode: 0 });
  assert.throws(() => manager.read({ sessionId: 'ssh-1' }), /already closed/);
  await manager.dispose();
});

await test('unknown session and tunnel ids throw actionable errors', async () => {
  const manager = new ConnectionManager({ subprocess: new FakeSubprocess({ onSpawn: () => fakeHandle() }) });
  assert.throws(() => manager.read({ sessionId: 'ssh-99' }), /Unknown SSH session/);
  await assert.rejects(() => manager.close({ sessionId: 'ssh-99' }), /unknown SSH session/);
  await assert.rejects(() => manager.tunnelClose({ tunnelId: 'tunnel-99' }), /unknown tunnel/);
  await manager.dispose();
});

await test('tunnelOpen forwards a local port and tunnelClose ends it', async () => {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const localPort = server.address().port;
  try {
    const handles = [];
    const subprocess = new FakeSubprocess({
      onSpawn: () => {
        const done = Promise.withResolvers();
        const handle = fakeHandle({ done: done.promise });
        handle.terminate = () => {
          handle.terminated = true;
          done.resolve({ exitCode: 0, signal: null });
        };
        handles.push(handle);
        return handle;
      },
    });
    const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
    const tunnel = await manager.tunnelOpen({ host: 'user@devbox', remotePort: 8080, localPort });
    assert.equal(tunnel.tunnelId, 'tunnel-1');
    assert.equal(tunnel.host, 'user@devbox');
    assert.equal(tunnel.localPort, localPort);
    assert.equal(tunnel.remoteHost, '127.0.0.1');
    assert.equal(tunnel.remotePort, 8080);
    assert.equal(tunnel.pid, 0);
    assert.equal(tunnel.localUrl, `http://127.0.0.1:${localPort}/`);

    const argv = subprocess.spawns[0].argv;
    assert.equal(argv[1], '-N');
    assert.ok(argv.includes('-L'));
    assert.equal(argv[argv.indexOf('-L') + 1], `127.0.0.1:${localPort}:127.0.0.1:8080`);
    assert.equal(argv.at(-1), 'user@devbox');
    assert.ok(argv.includes('ExitOnForwardFailure=yes'));

    assert.deepEqual(manager.tunnelList(), [
      {
        tunnelId: 'tunnel-1',
        host: 'user@devbox',
        localPort,
        remoteHost: '127.0.0.1',
        remotePort: 8080,
        pid: 0,
      },
    ]);
    assert.deepEqual(await manager.tunnelClose({ tunnelId: 'tunnel-1' }), { tunnelId: 'tunnel-1', closed: true });
    assert.deepEqual(manager.tunnelList(), []);
    assert.equal(handles[0].terminated, true);
    await manager.dispose();
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

await test('tunnelOpen terminates the child and reports ssh stderr on failure', async () => {
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolve);
  });
  const closedPort = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));

  const handles = [];
  const subprocess = new FakeSubprocess({
    onSpawn: () => {
      const done = Promise.withResolvers();
      const handle = fakeHandle({ stderr: 'bind: Address already in use\n', done: done.promise });
      handle.terminate = () => {
        handle.terminated = true;
        done.resolve({ exitCode: 255, signal: null });
      };
      handles.push(handle);
      return handle;
    },
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  await assert.rejects(
    () => manager.tunnelOpen({ host: 'devbox', remotePort: 8080, localPort: closedPort, readyTimeoutMs: 1000 }),
    /Address already in use|already in use/,
  );
  assert.equal(handles[0].terminated, true);
  assert.deepEqual(manager.tunnelList(), []);
  await manager.dispose();
});

await test('harness validates profile and ports before spawning', async () => {
  const subprocess = new FakeSubprocess({ onSpawn: () => fakeHandle() });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  await assert.rejects(
    () => manager.harness({ host: 'devbox', action: 'start', profile: 'web; rm -rf ~' }),
    /profile/,
  );
  await assert.rejects(
    () => manager.harness({ host: 'devbox', action: 'start', remotePort: 70000 }),
    /remotePort/,
  );
  await assert.rejects(() => manager.harness({ host: 'devbox', action: 'nope' }), /action/);
  assert.equal(subprocess.spawns.length, 0);
  await manager.dispose();
});

await test('harness status reports a missing dsh without starting anything', async () => {
  const subprocess = new FakeSubprocess({
    onSpawn: () => fakeHandle({ stdout: 'missing\n', done: Promise.resolve({ exitCode: 0, signal: null }) }),
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  const status = await manager.harness({ host: 'devbox', action: 'status' });
  assert.equal(status.action, 'status');
  assert.equal(status.host, 'devbox');
  assert.equal(status.installed, false);
  assert.equal(status.running, false);
  assert.match(status.message, /not installed/);
  assert.equal(subprocess.spawns.length, 1);
  assert.ok(subprocess.spawns[0].argv.at(-1).includes('sh -lc'));
  await manager.dispose();
});

await test('dispose terminates tracked children and blocks later calls', async () => {
  const handles = [];
  const subprocess = new FakeSubprocess({
    onSpawn: () => {
      const done = Promise.withResolvers();
      const handle = fakeHandle({ done: done.promise });
      handle.terminate = () => {
        handle.terminated = true;
        done.resolve({ exitCode: null, signal: 'SIGTERM' });
      };
      handles.push(handle);
      return handle;
    },
  });
  const manager = new ConnectionManager({ subprocess, home: 'C:\\home' });
  const opened = await manager.open({ host: 'devbox' });
  assert.equal(opened.status, 'running');
  assert.equal(handles.length, 1);
  assert.equal(handles[0].terminated, false);
  await manager.dispose();
  assert.equal(handles[0].terminated, true);
  assert.throws(() => manager.sessions(), /disposed/);
  await assert.rejects(() => manager.init(), /disposed/);
  await manager.dispose();
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
