// Scans every server in targets.txt inside a locked-down Docker container and
// stores one JSON result per server in research/results/ (git-ignored, because
// unpatched issues must stay private until disclosed).
//   node research/run.mjs [targets.txt] [--parallel 3]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync, spawn } from 'node:child_process';

const IMAGE = 'probe-research';
const list = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'research/targets.txt';
const out = 'research/results';
mkdirSync(out, { recursive: true });

const docker = (args, opts = {}) => spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });

if (docker(['info']).status !== 0) {
  console.error('Docker is not running. Start Docker Desktop and try again.');
  process.exit(2);
}
console.log('Building the isolated scanner image…');
if (docker(['build', '-q', '-t', IMAGE, '-f', 'research/Dockerfile', '.'], { stdio: 'inherit' }).status !== 0) process.exit(2);

const targets = readFileSync(list, 'utf8')
  .split('\n')
  .map((l) => l.replace(/#.*/, '').trim())
  .filter(Boolean);

// Runs one server in a locked-down container and resolves with the parsed result.
function scanOne(line) {
  const [pkg, ...args] = line.split(/\s+/);
  // No host mounts, no capabilities, limited memory/CPU/processes, writable /tmp only.
  const child = spawn('docker', [
    'run', '--rm', '--read-only', '--tmpfs', '/tmp:rw,exec,size=1g',
    '--memory', '1g', '--cpus', '1', '--pids-limit', '256',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    IMAGE, 'npx', '-y', pkg, ...args,
  ]);
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => (stdout += d));
  child.stderr.on('data', (d) => (stderr += d));
  const killer = setTimeout(() => child.kill("SIGKILL"), 300000);
  return new Promise((resolve) => {
    child.on('close', () => {
      clearTimeout(killer);
      let result;
      try {
        result = JSON.parse(stdout);
      } catch {
        result = { target: pkg, error: (stderr || 'no output').trim().split('\n').slice(-3).join(' ') };
      }
      result.package = pkg;
      result.scannedAt = new Date().toISOString();
      writeFileSync(`${out}/${pkg.replace(/[^a-z0-9.-]+/gi, '_')}.json`, JSON.stringify(result, null, 2));
      console.log(`${pkg.padEnd(50)} ${result.error ? `did not start (${result.error.slice(0, 60)})` : `${result.tools.length} tools · ${result.findings.length} findings`}`);
      resolve(result);
    });
  });
}

const parallel = Number(process.argv[process.argv.indexOf('--parallel') + 1]) || 3;
const queue = [...targets];
await Promise.all(Array.from({ length: parallel }, async () => {
  while (queue.length) await scanOne(queue.shift());
}));
console.log(`\nResults in ${out}/. Next: node research/aggregate.mjs`);
