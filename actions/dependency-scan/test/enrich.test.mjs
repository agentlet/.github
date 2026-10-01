import { describe, test } from 'node:test';
import { expect } from '../testlib/expect.mjs';
import { EPSS_BATCH_SIZE, chunk, fetchEpss, fetchKev } from '../lib/enrich.mjs';

const ok = body => async () => ({ ok: true, status: 200, json: async () => body });
const silent = () => {};

describe('chunk', () => {
    test('splits into fixed-size pieces', () => {
        expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
        expect(chunk([], 2)).toEqual([]);
    });
});

describe('fetchEpss', () => {
    const ids = n => Array.from({ length: n }, (_, i) => `CVE-2024-${String(i).padStart(5, '0')}`);

    test('batches by 100 and passes an explicit limit on every request', async () => {
        const urls = [];
        const fetchImpl = async url => {
            urls.push(url);
            const requested = new URL(url).searchParams.get('cve').split(',');
            return { ok: true, json: async () => ({ data: requested.map(cve => ({ cve, epss: '0.5' })) }) };
        };
        const map = await fetchEpss(ids(250), { fetchImpl, warn: silent });
        expect(EPSS_BATCH_SIZE).toBe(100);
        expect(urls).toHaveLength(3);
        expect(urls.map(u => new URL(u).searchParams.get('cve').split(',').length)).toEqual([100, 100, 50]);
        expect(urls.every(u => new URL(u).searchParams.get('limit') === '100')).toBe(true);
        expect(Object.keys(map)).toHaveLength(250);
        expect(map['CVE-2024-00249']).toBe(0.5);
    });

    test('degrades to an empty map (with a warning) on a network failure', async () => {
        const warnings = [];
        const map = await fetchEpss(ids(3), {
            fetchImpl: async () => { throw new Error('offline'); },
            warn: msg => warnings.push(msg)
        });
        expect(map).toEqual({});
        expect(warnings).toHaveLength(1);
        expect(warnings[0]).toContain('EPSS enrichment unavailable');
    });

    test('degrades on a non-2xx response', async () => {
        const map = await fetchEpss(ids(1), { fetchImpl: async () => ({ ok: false, status: 503 }), warn: silent });
        expect(map).toEqual({});
    });

    test('does no request when offline or when there is nothing to look up', async () => {
        const fetchImpl = async () => { throw new Error('must not be called'); };
        expect(await fetchEpss(ids(3), { offline: true, fetchImpl })).toEqual({});
        expect(await fetchEpss([], { fetchImpl })).toEqual({});
    });
});

describe('fetchKev', () => {
    test('returns the set of KEV cve ids', async () => {
        const kev = await fetchKev({ fetchImpl: ok({ vulnerabilities: [{ cveID: 'CVE-1' }, { cveID: 'CVE-2' }] }), warn: silent });
        expect([...kev].sort()).toEqual(['CVE-1', 'CVE-2']);
    });

    test('degrades to an empty set on failure', async () => {
        const warnings = [];
        const kev = await fetchKev({ fetchImpl: async () => { throw new Error('boom'); }, warn: m => warnings.push(m) });
        expect(kev.size).toBe(0);
        expect(warnings[0]).toContain('KEV enrichment unavailable');
    });

    test('is skipped offline', async () => {
        const kev = await fetchKev({ offline: true, fetchImpl: async () => { throw new Error('must not be called'); } });
        expect(kev.size).toBe(0);
    });
});
