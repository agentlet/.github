// Tests of bin/sbom-from-esbuild-metafile.mjs on a throwaway node_modules tree.

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from '../../dependency-scan/testlib/expect.mjs';
import { parseSbomArgs, licenseOf } from '../../dependency-scan/lib/esbuild-sbom.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', '..', 'dependency-scan', 'bin', 'sbom-from-esbuild-metafile.mjs');

let root;
const write = (rel, content) => {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    writeFileSync(path.join(root, rel), typeof content === 'string' ? content : JSON.stringify(content));
};
const metafile = (...inputs) => ({ inputs: Object.fromEntries(inputs.map(i => [i, { bytes: 1 }])) });

before(() => {
    root = mkdtempSync(path.join(tmpdir(), 'sbom-esbuild-'));
    write('package.json', { name: 'my-lib', version: '3.2.1', description: 'a library' });
    write('node_modules/xlsx/package.json', { name: 'xlsx', version: '0.18.5', license: 'Apache-2.0', description: 'sheets' });
    write('node_modules/@scope/pkg/package.json', { name: '@scope/pkg', version: '1.0.0', license: '(MIT OR Apache-2.0)' });
    write('node_modules/foo/package.json', { name: 'foo', version: '2.0.0', licenses: [{ type: 'ISC' }] });
    write('node_modules/foo/node_modules/@scope/pkg/package.json', { name: '@scope/pkg', version: '2.0.0', license: { type: 'MIT' } });
    write('meta/a.meta.json', metafile(
        'src/index.ts', 'node_modules/xlsx/xlsx.js', 'node_modules/xlsx/dist/extra.js', 'node_modules/@scope/pkg/index.js'
    ));
    write('meta/b.meta.json', metafile(
        'node_modules/xlsx/xlsx.js', 'node_modules/foo/node_modules/@scope/pkg/index.js', 'node_modules/ghost/index.js'
    ));
});
after(() => { rmSync(root, { recursive: true, force: true }); });

function run(args, cwd = root) {
    return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
}
const read = rel => JSON.parse(readFileSync(path.join(root, rel), 'utf8'));

describe('sbom-from-esbuild-metafile CLI', () => {
    test('resolves scoped and nested packages across several metafiles, deduped, with purls and licenses', () => {
        const r = run(['--root=.', '--out=out/sbom.cdx.json', 'meta/a.meta.json', 'meta/b.meta.json']);
        expect(r.status).toBe(0);
        const sbom = read('out/sbom.cdx.json');
        expect(sbom.bomFormat).toBe('CycloneDX');
        expect(sbom.specVersion).toBe('1.5');
        expect(sbom.components.map(c => c.purl).sort()).toEqual([
            'pkg:npm/%40scope/pkg@1.0.0',
            'pkg:npm/%40scope/pkg@2.0.0',
            'pkg:npm/xlsx@0.18.5'
        ]);
        const byPurl = Object.fromEntries(sbom.components.map(c => [c.purl, c]));
        expect(byPurl['pkg:npm/%40scope/pkg@1.0.0'].licenses).toEqual([{ expression: '(MIT OR Apache-2.0)' }]);
        expect(byPurl['pkg:npm/%40scope/pkg@2.0.0'].licenses).toEqual([{ license: { id: 'MIT' } }]);
        expect(byPurl['pkg:npm/xlsx@0.18.5'].licenses).toEqual([{ license: { id: 'Apache-2.0' } }]);
        // a package with no package.json on disk is skipped with a warning
        expect(r.stderr).toContain('node_modules/ghost');
    });

    test('metadata.component defaults to the root package.json', () => {
        run(['--out=out/default.cdx.json', 'meta/a.meta.json']);
        const sbom = read('out/default.cdx.json');
        expect(sbom.metadata.component).toMatchObject({ name: 'my-lib', version: '3.2.1', purl: 'pkg:npm/my-lib@3.2.1', description: 'a library' });
    });

    test('--name and --version override the defaults', () => {
        run(['--name=@acme/site', '--version=0.0.1', '--out=out/named.cdx.json', 'meta/a.meta.json']);
        const sbom = read('out/named.cdx.json');
        expect(sbom.metadata.component.purl).toBe('pkg:npm/%40acme/site@0.0.1');
        expect(sbom.metadata.component.description).toBeUndefined();
    });

    test('accepts a newline/comma separated --metafile list', () => {
        const r = run(['--metafile=meta/a.meta.json,\nmeta/b.meta.json', '--out=out/list.cdx.json']);
        expect(r.status).toBe(0);
        expect(read('out/list.cdx.json').components).toHaveLength(3);
    });

    test('writes sbom-path to $GITHUB_OUTPUT', () => {
        const file = path.join(root, 'gh-out.txt');
        writeFileSync(file, '');
        const r = spawnSync(process.execPath, [CLI, '--out=out/o.cdx.json', 'meta/a.meta.json'], {
            cwd: root, encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: file }
        });
        expect(r.status).toBe(0);
        expect(readFileSync(file, 'utf8')).toBe('sbom-path=out/o.cdx.json\n');
    });

    test('fails clearly on a missing metafile', () => {
        const r = run(['meta/nope.json']);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('metafile not found');
    });

    test('fails when the component name cannot be determined', () => {
        const bare = mkdtempSync(path.join(tmpdir(), 'sbom-bare-'));
        writeFileSync(path.join(bare, 'm.json'), JSON.stringify(metafile('src/a.ts')));
        const r = run(['m.json'], bare);
        rmSync(bare, { recursive: true, force: true });
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('--name and --version');
    });
});

describe('parseSbomArgs / licenseOf', () => {
    test('requires at least one metafile', () => {
        assert.throws(() => parseSbomArgs([]), /at least one/);
    });

    test('rejects unknown flags', () => {
        assert.throws(() => parseSbomArgs(['--bogus=1', 'm.json']), /Unknown argument/);
    });

    test('reads the license from the three package.json shapes', () => {
        expect(licenseOf({ license: 'MIT' })).toBe('MIT');
        expect(licenseOf({ license: { type: 'ISC' } })).toBe('ISC');
        expect(licenseOf({ licenses: [{ type: 'BSD' }] })).toBe('BSD');
        expect(licenseOf({})).toBeUndefined();
    });
});
