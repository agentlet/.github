import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { expect } from '../testlib/expect.mjs';
import { splitList, parseArgs, normalizeExceptions } from '../lib/cli.mjs';

describe('splitList', () => {
    test('splits on newlines and commas, trims, drops empties', () => {
        expect(splitList('a.json\n b.json ,c.json,\n\n')).toEqual(['a.json', 'b.json', 'c.json']);
    });

    test('handles empty and undefined', () => {
        expect(splitList('')).toEqual([]);
        expect(splitList(undefined)).toEqual([]);
    });
});

describe('parseArgs', () => {
    test('applies the documented defaults', () => {
        expect(parseArgs(['--blocking-sbom=a.cdx.json'])).toEqual({
            minSeverity: 'high',
            blockingSboms: ['a.cdx.json'],
            blockingLockfile: false,
            lockfile: 'package-lock.json',
            exceptions: 'security/vulnerability-exceptions.json',
            outDir: 'reports/security',
            sarifLocation: '',
            offline: false,
            exitZero: false
        });
    });

    test('accepts --flag=value and --flag value, and repeated --blocking-sbom', () => {
        const options = parseArgs(['--blocking-sbom', 'a.cdx.json', '--blocking-sbom=b.cdx.json\nc.cdx.json', '--out-dir', 'out']);
        expect(options.blockingSboms).toEqual(['a.cdx.json', 'b.cdx.json', 'c.cdx.json']);
        expect(options.outDir).toBe('out');
    });

    test('--lockfile= (empty) skips the reporting scope', () => {
        expect(parseArgs(['--blocking-sbom=a.cdx.json', '--lockfile=']).lockfile).toBe('');
    });

    test('boolean flags may be bare or explicit', () => {
        const options = parseArgs(['--blocking-lockfile=true', '--offline', '--exit-zero=false']);
        expect(options).toMatchObject({ blockingLockfile: true, offline: true, exitZero: false });
    });

    test('--blocking-lockfile=false with no SBOM is an error', () => {
        assert.throws(() => parseArgs(['--blocking-lockfile=false']), /Nothing is blocking/);
    });

    test('rejects unknown flags so a typo cannot weaken the gate', () => {
        assert.throws(() => parseArgs(['--blocking-sbom=a.cdx.json', '--min-sevrity=low']), /Unknown argument/);
    });

    test('rejects an invalid severity', () => {
        assert.throws(() => parseArgs(['--blocking-sbom=a', '--min-severity=severe']), /Invalid --min-severity/);
    });

    test('rejects a blocking lockfile with an empty lockfile path', () => {
        assert.throws(() => parseArgs(['--blocking-lockfile', '--lockfile=']), /must not be empty/);
    });

    test('rejects a value flag with no value', () => {
        assert.throws(() => parseArgs(['--blocking-sbom']), /Missing value/);
    });

    test('rejects a bad boolean', () => {
        assert.throws(() => parseArgs(['--blocking-lockfile=maybe']), /Use true or false/);
    });
});

describe('normalizeExceptions', () => {
    const full = { id: 'GHSA-a', reason: 'r', expires: '2099-01-01', owner: 'o' };

    test('accepts an object with an exceptions array or a bare array', () => {
        expect(normalizeExceptions({ exceptions: [full] }).list).toEqual([full]);
        expect(normalizeExceptions([full]).list).toEqual([full]);
        expect(normalizeExceptions({}).list).toEqual([]);
    });

    test('warns about entries missing owner, reason or expiry', () => {
        const { warnings } = normalizeExceptions([{ id: 'GHSA-a' }]);
        expect(warnings).toHaveLength(3);
    });

    test('warns about a malformed expiry date', () => {
        const { warnings } = normalizeExceptions([{ ...full, expires: 'next year' }]);
        expect(warnings).toHaveLength(1);
    });

    test('does not warn for a complete entry', () => {
        expect(normalizeExceptions([full]).warnings).toEqual([]);
    });

    test('throws on an entry without an id or a non-array "exceptions"', () => {
        assert.throws(() => normalizeExceptions([{ reason: 'x' }]), /no "id"/);
        assert.throws(() => normalizeExceptions({ exceptions: 'nope' }), /array/);
    });
});
