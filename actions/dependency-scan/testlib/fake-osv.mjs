#!/usr/bin/env node
/**
 * Stand-in for the osv-scanner binary, used by test/scan-cli.test.mjs via
 * $OSV_SCANNER_BIN. Understands `--version` and
 * `scan source --format json -L <file>` where <file> is a CycloneDX SBOM
 * (*.cdx.json) or a package-lock.json, and answers with real-shaped OSV
 * records for xlsx and ws. Like the real tool it exits 1 when it reports
 * vulnerabilities. Each invocation's arguments are appended to
 * $FAKE_OSV_LOG when set.
 */

import { appendFileSync, readFileSync } from 'node:fs';

const XLSX = [
    {
        id: 'GHSA-4r6h-8v6p-xvw6',
        aliases: ['CVE-2023-30533'],
        summary: 'Prototype Pollution in sheetJS',
        database_specific: { severity: 'HIGH' },
        affected: [{
            package: { name: 'xlsx', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
            database_specific: { last_known_affected_version_range: '< 0.19.3' }
        }],
        references: [{ type: 'ADVISORY', url: 'https://example.com/GHSA-4r6h-8v6p-xvw6' }]
    },
    {
        id: 'GHSA-5pgg-2g8v-p4x9',
        aliases: ['CVE-2024-22363'],
        summary: 'xlsx Regular Expression Denial of Service (ReDoS)',
        database_specific: { severity: 'HIGH' },
        affected: [{
            package: { name: 'xlsx', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
            database_specific: { last_known_affected_version_range: '< 0.20.2' }
        }],
        references: []
    }
];

const WS = [{
    id: 'GHSA-96hv-2xvq-fx4p',
    aliases: ['CVE-2026-48779'],
    summary: 'ws: Memory exhaustion DoS',
    database_specific: { severity: 'HIGH' },
    affected: [
        { package: { name: 'ws', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '7.0.0' }, { fixed: '7.5.11' }] }] },
        { package: { name: 'ws', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '8.0.0' }, { fixed: '8.21.0' }] }] }
    ],
    references: []
}];

const DB = { xlsx: XLSX, ws: WS };

const args = process.argv.slice(2);
if (process.env.FAKE_OSV_LOG) {
    appendFileSync(process.env.FAKE_OSV_LOG, JSON.stringify(args) + '\n');
}

if (args[0] === '--version') {
    console.log('osv-scanner version: fake');
    process.exit(0);
}

const target = args[args.indexOf('-L') + 1];
if (!target) {
    console.error('fake-osv: expected -L <file>');
    process.exit(127);
}
const doc = JSON.parse(readFileSync(target, 'utf8'));

let installed = [];
if (target.endsWith('.cdx.json')) {
    installed = (doc.components || []).map(c => ({ name: c.name, version: c.version }));
} else {
    installed = Object.entries(doc.packages || {})
        .filter(([key]) => key.startsWith('node_modules/'))
        .map(([key, value]) => ({ name: key.split('node_modules/').pop(), version: value.version }));
}

const packages = installed
    .filter(pkg => DB[pkg.name])
    .map(pkg => ({
        package: { name: pkg.name, version: pkg.version, ecosystem: 'npm' },
        vulnerabilities: DB[pkg.name]
    }));

console.log(JSON.stringify({ results: [{ source: { path: target, type: 'lockfile' }, packages }] }));
process.exit(packages.length > 0 ? 1 : 0);
