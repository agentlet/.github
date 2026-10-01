// End-to-end tests of bin/scan.mjs against a fake osv-scanner (see
// testlib/fake-osv.mjs) with --offline, so they need no network.

import { describe, test, before, after } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from '../testlib/expect.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const SCAN = path.join(here, '..', 'bin', 'scan.mjs');
const FAKE_OSV = path.join(here, '..', 'testlib', 'fake-osv.mjs');

let work;
before(() => { work = mkdtempSync(path.join(tmpdir(), 'dep-scan-')); });
after(() => { rmSync(work, { recursive: true, force: true }); });

function sbom(name, components) {
    return { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { component: { name } }, components };
}
const comp = (name, version) => ({ type: 'library', name, version, purl: `pkg:npm/${name}@${version}` });

function lockfile(deps) {
    const packages = { '': { name: 'app', version: '1.0.0' } };
    for (const [name, version] of Object.entries(deps)) {
        packages[`node_modules/${name}`] = { version };
    }
    return { name: 'app', version: '1.0.0', lockfileVersion: 3, packages };
}

function setup(files) {
    const dir = mkdtempSync(path.join(work, 'case-'));
    for (const [name, content] of Object.entries(files)) {
        mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
        writeFileSync(path.join(dir, name), typeof content === 'string' ? content : JSON.stringify(content));
    }
    return dir;
}

function run(dir, args) {
    const out = path.join(dir, 'github-output.txt');
    writeFileSync(out, '');
    const result = spawnSync(process.execPath, [SCAN, '--offline', ...args], {
        cwd: dir,
        encoding: 'utf8',
        env: { ...process.env, OSV_SCANNER_BIN: FAKE_OSV, GITHUB_OUTPUT: out, FAKE_OSV_LOG: path.join(dir, 'osv.log') }
    });
    const outputs = Object.fromEntries(
        readFileSync(out, 'utf8').split('\n').filter(Boolean).map(l => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)])
    );
    const report = existsSync(path.join(dir, 'reports/security/scan-report.json'))
        ? JSON.parse(readFileSync(path.join(dir, 'reports/security/scan-report.json'), 'utf8'))
        : null;
    return { ...result, outputs, report };
}

describe('bin/scan.mjs: SBOM blocking scope', () => {
    test('fails the gate for xlsx 0.18.5 and exposes outputs, SARIF and report', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.18.5')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.status).toBe(1);
        expect(r.outputs['gate-outcome']).toBe('fail');
        expect(r.outputs['blocking-count']).toBe('2');
        expect(r.outputs['report-path']).toBe('reports/security/scan-report.json');
        expect(r.outputs['sarif-path']).toBe('reports/security/results.sarif');
        const sarif = JSON.parse(readFileSync(path.join(dir, 'reports/security/results.sarif'), 'utf8'));
        expect(sarif.runs[0].results).toHaveLength(2);
        expect(r.report.blocking.blockingFindings).toHaveLength(2);
        expect(r.report.reporting).toBeNull();
    });

    test('--exit-zero keeps exit code 0 but still reports the failure', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.18.5')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=', '--exit-zero']);
        expect(r.status).toBe(0);
        expect(r.outputs['gate-outcome']).toBe('fail');
    });

    test('passes when the patched version is installed (excluded per advisory range)', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.20.3')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.status).toBe(0);
        expect(r.outputs['gate-outcome']).toBe('pass');
        expect(r.outputs['blocking-count']).toBe('0');
        expect(r.report.blocking.notAffected).toHaveLength(2);
        const sarif = JSON.parse(readFileSync(path.join(dir, 'reports/security/results.sarif'), 'utf8'));
        expect(sarif.runs[0].results).toEqual([]);
    });

    test('scans through -L (not the deprecated --sbom) on a *.cdx.json file', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.20.3')]) });
        run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        const calls = readFileSync(path.join(dir, 'osv.log'), 'utf8').trim().split('\n').map(l => JSON.parse(l));
        const scan = calls.find(c => c[0] === 'scan');
        expect(scan.includes('--sbom')).toBe(false);
        expect(scan[scan.indexOf('-L') + 1].endsWith('.cdx.json')).toBe(true);
    });

    test('merges several SBOMs (repeated flag, newline list) and dedupes by purl', () => {
        const dir = setup({
            'a.cdx.json': sbom('a', [comp('xlsx', '0.18.5'), comp('is-number', '7.0.0')]),
            'b.cdx.json': sbom('b', [comp('xlsx', '0.18.5'), comp('ws', '8.18.3')]),
            'c.cdx.json': sbom('c', [comp('ms', '2.1.3')])
        });
        const r = run(dir, ['--blocking-sbom=a.cdx.json', '--blocking-sbom=b.cdx.json\nc.cdx.json', '--lockfile=']);
        expect(r.status).toBe(1);
        const merged = JSON.parse(readFileSync(path.join(dir, 'reports/security/sbom-blocking-merged.cdx.json'), 'utf8'));
        expect(merged.components.map(c => c.purl)).toEqual([
            'pkg:npm/is-number@7.0.0', 'pkg:npm/ms@2.1.3', 'pkg:npm/ws@8.18.3', 'pkg:npm/xlsx@0.18.5'
        ]);
        // xlsx twice in the inputs, counted once: 2 xlsx GHSAs + ws.
        const ids = r.report.blocking.blockingFindings.map(f => `${f.packageName}:${f.id}`).sort();
        expect(ids).toEqual([
            'ws:GHSA-96hv-2xvq-fx4p', 'xlsx:GHSA-4r6h-8v6p-xvw6', 'xlsx:GHSA-5pgg-2g8v-p4x9'
        ]);
    });

    test('a vulnerable package in a second SBOM alone fails the gate', () => {
        const dir = setup({
            'clean.cdx.json': sbom('clean', [comp('ms', '2.1.3')]),
            'bad.cdx.json': sbom('bad', [comp('ws', '8.18.3')])
        });
        const r = run(dir, ['--blocking-sbom=clean.cdx.json,bad.cdx.json', '--lockfile=']);
        expect(r.outputs['gate-outcome']).toBe('fail');
        expect(r.report.blocking.blockingFindings[0].fixedVersion).toBe('8.21.0');
    });

    test('components without a purl are reported as not scannable, not dropped silently or fatal', () => {
        const dir = setup({
            'cdn.cdx.json': sbom('site', [
                comp('ms', '2.1.3'),
                { type: 'library', name: 'chart-from-cdnjs', version: '4.5.1' },
                { type: 'library', name: 'no-version-purl', purl: 'pkg:npm/no-version-purl' }
            ])
        });
        const r = run(dir, ['--blocking-sbom=cdn.cdx.json', '--lockfile=']);
        expect(r.status).toBe(0);
        expect(r.stderr).toContain('cannot be scanned');
        expect(r.report.unscannable.map(c => c.name).sort()).toEqual(['chart-from-cdnjs', 'no-version-purl']);
        const summary = readFileSync(path.join(dir, 'reports/security/scan-summary.md'), 'utf8');
        expect(summary).toContain('Not scannable');
        expect(summary).toContain('chart-from-cdnjs@4.5.1');
    });

    test('an SBOM with only unscannable components passes without calling the scanner for it', () => {
        const dir = setup({ 'cdn.cdx.json': sbom('site', [{ type: 'library', name: 'x', version: '1' }]) });
        const r = run(dir, ['--blocking-sbom=cdn.cdx.json', '--lockfile=']);
        expect(r.status).toBe(0);
        expect(r.outputs['gate-outcome']).toBe('pass');
    });

    test('a missing blocking SBOM is an error (exit 2), not a pass', () => {
        const dir = setup({});
        const r = run(dir, ['--blocking-sbom=nope.cdx.json', '--lockfile=']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('Blocking SBOM not found');
        expect(r.outputs['gate-outcome']).toBeUndefined();
    });
});

describe('bin/scan.mjs: lockfile scope', () => {
    test('reporting scope never blocks, even for vulnerable packages', () => {
        const dir = setup({
            'sbom.cdx.json': sbom('app', [comp('ms', '2.1.3')]),
            'package-lock.json': lockfile({ xlsx: '0.18.5' })
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json']);
        expect(r.status).toBe(0);
        expect(r.outputs['gate-outcome']).toBe('pass');
        expect(r.report.reporting.nonBlockingFindings).toHaveLength(2);
        expect(r.report.reporting.blockingFindings).toHaveLength(0);
        // ...but they are in SARIF, with the lockfile as location.
        const sarif = JSON.parse(readFileSync(path.join(dir, 'reports/security/results.sarif'), 'utf8'));
        expect(sarif.runs[0].results).toHaveLength(2);
        expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('package-lock.json');
    });

    test('an empty --lockfile cleanly skips the reporting scope (no lockfile in the repo)', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('ms', '2.1.3')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.status).toBe(0);
        expect(r.report.reporting).toBeNull();
        expect(r.stderr.includes('no lockfile')).toBe(false);
    });

    test('a missing default lockfile only warns', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('ms', '2.1.3')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json']);
        expect(r.status).toBe(0);
        expect(r.stderr).toContain('no lockfile found');
    });

    test('--blocking-lockfile makes every lockfile finding blocking', () => {
        const dir = setup({ 'package-lock.json': lockfile({ xlsx: '0.18.5', ws: '8.18.3', ms: '2.1.3' }) });
        const r = run(dir, ['--blocking-lockfile']);
        expect(r.status).toBe(1);
        expect(r.outputs['gate-outcome']).toBe('fail');
        expect(r.outputs['blocking-count']).toBe('3');
        expect(r.report.blockingScopes).toEqual(['lockfile']);
        expect(r.report.reporting).toBeNull();
    });

    test('--blocking-lockfile passes on a clean lockfile', () => {
        const dir = setup({ 'package-lock.json': lockfile({ xlsx: '0.20.3', ms: '2.1.3' }) });
        const r = run(dir, ['--blocking-lockfile']);
        expect(r.status).toBe(0);
        expect(r.outputs['gate-outcome']).toBe('pass');
    });

    test('--blocking-lockfile needs the lockfile to exist', () => {
        const dir = setup({});
        const r = run(dir, ['--blocking-lockfile']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('Blocking lockfile not found');
    });

    test('SBOM and lockfile both blocking: a finding in both is counted once', () => {
        const dir = setup({
            'sbom.cdx.json': sbom('app', [comp('xlsx', '0.18.5')]),
            'package-lock.json': lockfile({ xlsx: '0.18.5', ws: '8.18.3' })
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--blocking-lockfile']);
        expect(r.outputs['blocking-count']).toBe('3');
        expect(r.report.blockingScopes).toEqual(['bundle', 'lockfile']);
    });
});

describe('bin/scan.mjs: exceptions', () => {
    const base = { 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.18.5')]) };

    test('valid exceptions exempt the findings', () => {
        const dir = setup({
            ...base,
            'security/vulnerability-exceptions.json': { exceptions: [
                { id: 'GHSA-4r6h-8v6p-xvw6', package: 'xlsx', reason: 'r', expires: '2999-01-01', owner: 'o' },
                { id: 'CVE-2024-22363', package: 'xlsx', reason: 'r', expires: '2999-01-01', owner: 'o' }
            ] }
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.outputs['gate-outcome']).toBe('pass');
        expect(r.report.blocking.exemptedFindings).toHaveLength(2);
    });

    test('an expired exception fails the gate', () => {
        const dir = setup({
            'sbom.cdx.json': sbom('app', [comp('ms', '2.1.3')]),
            'security/vulnerability-exceptions.json': [
                { id: 'GHSA-old', reason: 'r', expires: '2020-01-01', owner: 'o' }
            ]
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.outputs['gate-outcome']).toBe('fail');
        expect(r.outputs['blocking-count']).toBe('0');
        expect(r.report.blocking.expiredExceptions).toHaveLength(1);
    });

    test('an unused exception only warns', () => {
        const dir = setup({
            'sbom.cdx.json': sbom('app', [comp('ms', '2.1.3')]),
            'security/vulnerability-exceptions.json': { exceptions: [
                { id: 'GHSA-unused', reason: 'r', expires: '2999-01-01', owner: 'o' }
            ] }
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=']);
        expect(r.outputs['gate-outcome']).toBe('pass');
        expect(r.stdout).toContain('unused exception');
    });

    test('a custom --exceptions path is honoured', () => {
        const dir = setup({
            ...base,
            'custom/ex.json': { exceptions: [
                { id: 'GHSA-4r6h-8v6p-xvw6', reason: 'r', expires: '2999-01-01', owner: 'o' },
                { id: 'GHSA-5pgg-2g8v-p4x9', reason: 'r', expires: '2999-01-01', owner: 'o' }
            ] }
        });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=', '--exceptions=custom/ex.json']);
        expect(r.outputs['gate-outcome']).toBe('pass');
    });
});

describe('bin/scan.mjs: arguments', () => {
    test('nothing blocking is an error', () => {
        const dir = setup({});
        const r = run(dir, ['--lockfile=']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('Nothing is blocking');
    });

    test('--out-dir and --min-severity are honoured', () => {
        const dir = setup({ 'sbom.cdx.json': sbom('app', [comp('xlsx', '0.18.5')]) });
        const r = run(dir, ['--blocking-sbom=sbom.cdx.json', '--lockfile=', '--out-dir=out/here', '--min-severity=critical']);
        // The xlsx advisories are high, so they no longer block at critical.
        expect(r.outputs['gate-outcome']).toBe('pass');
        expect(r.outputs['report-path']).toBe('out/here/scan-report.json');
        expect(existsSync(path.join(dir, 'out/here/results.sarif'))).toBe(true);
    });
});
