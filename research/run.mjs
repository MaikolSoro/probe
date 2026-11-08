// Scans every server in targets.txt inside a locked-down Docker container and
// stores one JSON result per server in research/results/ (git-ignored, because
// unpatched issues must stay private until disclosed).
//   node research/run.mjs [targets.txt]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const IMAGE = 'probe-research';
const list = process.argv[2] ?? 'research/targets.txt';
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

for (const line of targets) {
  const [pkg, ...args] = line.split(/\s+/);
  const slug = pkg.replace(/[^a-z0-9.-]+/gi, '_');
  process.stdout.write(`${pkg.padEnd(50)} `);
  // No host mounts, no capabilities, limited memory/CPU/processes, writable /tmp only.
  const run = docker(
    [
      'run', '--rm', '--read-only', '--tmpfs', '/tmp:rw,exec,size=1g',
      '--memory', '1g', '--cpus', '1', '--pids-limit', '256',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      IMAGE, 'npx', '-y', pkg, ...args,
    ],
    { timeout: 240000 },
  );
  let result;
  try {
    result = JSON.parse(run.stdout);
  } catch {
    result = { target: pkg, error: (run.stderr || run.error?.message || 'no output').trim().split('\n').slice(-3).join(' ') };
  }
  result.package = pkg;
  result.scannedAt = new Date().toISOString();
  writeFileSync(`${out}/${slug}.json`, JSON.stringify(result, null, 2));
  console.log(result.error ? `did not start (${result.error.slice(0, 60)})` : `${result.tools.length} tools · ${result.findings.length} findings`);
}
console.log(`\nResults in ${out}/. Next: node research/aggregate.mjs`);
