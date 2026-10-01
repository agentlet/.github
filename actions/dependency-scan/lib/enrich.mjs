/**
 * Best-effort EPSS and CISA KEV enrichment. Every network failure degrades
 * to "unknown" with a warning, never to a scan failure.
 */

// api.first.org's EPSS endpoint pages results at 100 per request by
// default (its own `limit`/`offset` params). Passing more CVE ids than
// that in one `?cve=` query would silently only get scores back for the
// first page. Chunk defensively and pass an explicit `limit` so a scan
// with a large, EPSS-scored CVE count never truncates.
const EPSS_BATCH_SIZE = 100;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function chunk(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}

async function fetchEpssBatch(cveIds, fetchImpl) {
    const url = `https://api.first.org/data/v1/epss?cve=${cveIds.join(',')}&limit=${EPSS_BATCH_SIZE}`;
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    const body = await response.json();
    const map = {};
    for (const entry of body.data || []) {
        map[entry.cve] = Number(entry.epss);
    }
    return map;
}

async function fetchEpss(cveIds, { offline = false, fetchImpl = fetch, warn = console.warn } = {}) {
    if (offline || cveIds.length === 0) {
        return {};
    }
    try {
        const batches = await Promise.all(
            chunk(cveIds, EPSS_BATCH_SIZE).map(batch => fetchEpssBatch(batch, fetchImpl))
        );
        return Object.assign({}, ...batches);
    } catch (error) {
        warn(`EPSS enrichment unavailable (${error.message}); marking EPSS as unknown.`);
        return {};
    }
}

async function fetchKev({ offline = false, fetchImpl = fetch, warn = console.warn } = {}) {
    if (offline) {
        return new Set();
    }
    try {
        const response = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const body = await response.json();
        return new Set((body.vulnerabilities || []).map(v => v.cveID));
    } catch (error) {
        warn(`CISA KEV enrichment unavailable (${error.message}); marking KEV as unknown.`);
        return new Set();
    }
}

export { EPSS_BATCH_SIZE, chunk, fetchEpss, fetchKev };
