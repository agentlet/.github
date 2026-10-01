#!/usr/bin/env node
/**
 * Dependency vulnerability scan + blocking quality gate.
 *
 * Runs osv-scanner (must be on PATH, or named by $OSV_SCANNER_BIN) over up
 * to two scopes:
 *
 *  - blocking scope, one of (or both):
 *      --blocking-sbom=<path>   CycloneDX SBOM(s) listing what you SHIP.
 *                               Repeatable and/or newline/comma separated;
 *                               several are merged and deduplicated by purl.
 *      --blocking-lockfile      the whole lockfile is the blocking scope
 *                               (repos where everything runs on a developer
 *                               machine).
 *  - reporting scope: --lockfile=<path> (default package-lock.json), never
 *    blocks, unless --blocking-lockfile is set. Pass --lockfile= (empty) to
 *    skip it.
 *
 * Findings are enriched with EPSS and CISA KEV status, best-effort: a
 * network failure is a warning, never a scan failure. The pure
 * severity/gate/SARIF logic lives in lib/gate-core.mjs.
 *
 * Other options:
 *   --min-severity=<low|medium|high|critical>  default: high
 *   --exceptions=<path>    default: security/vulnerability-exceptions.json
 *                          (a missing file means no exceptions)
 *   --out-dir=<path>       default: reports/security
 *   --sarif-location=<p>   repo file SARIF results point at for the blocking
 *                          SBOM scope (default: package.json when it exists,
 *                          otherwise the first blocking SBOM)
 *   --offline              skip EPSS/KEV network enrichment
 *   --exit-zero            exit 0 even when the gate fails (the action reads
 *                          the gate-outcome output instead)
 *
 * Exit codes: 0 gate passed (or --exit-zero), 1 gate failed, 2 error.
 * When $GITHUB_OUTPUT is set, writes gate-outcome, blocking-count,
 * report-path and sarif-path to it.
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
    parseOsvScanOutput,
    partitionByAffected,
    enrichFindings,
    evaluateGate,
    buildSarif
} from '../lib/gate-core.mjs';
import { parseArgs, normalizeExceptions } from '../lib/cli.mjs';
import { mergeSboms } from '../lib/sbom-merge.mjs';
import { fetchEpss, fetchKev } from '../lib/enrich.mjs';
import { formatTable, formatNotAffected, buildMarkdownSummary } from '../lib/report.mjs';

const SCANNER_VERSION = '1.0.0';
const OSV_BIN = process.env.OSV_SCANNER_BIN || 'osv-scanner';

function checkOsvScannerAvailable() {
    try {
        execFileSync(OSV_BIN, ['--version'], { stdio: 'pipe' });
    } catch {
        throw new Error([
            `${OSV_BIN} is not available.`,
            '  Install it locally with: brew install osv-scanner',
            '  (the dependency-scan action installs a pinned, checksum-verified release binary).'
        ].join('\n'));
    }
}

/**
 * Run `osv-scanner scan source` against either an SBOM or a lockfile and
 * return its parsed JSON output. osv-scanner exits non-zero whenever it
 * finds any vulnerability at all, which is expected and not an error here
 * (we compute our own gate from the JSON); only a missing/invalid target
 * or a JSON parse failure is a hard failure.
 */
function runOsvScanner({ sbomPath, lockfilePath }) {
    // `--sbom` is deprecated in osv-scanner 2.x: SBOMs go through `-L` too
    // and are recognised by file name (*.cdx.json), which the merged SBOM
    // written by main() always has.
    const args = ['scan', 'source', '--format', 'json', '-L', sbomPath || lockfilePath];

    let stdout;
    try {
        stdout = execFileSync(OSV_BIN, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
        // Exit 1 means "vulnerabilities found": stdout still has the JSON.
        // Any other failure (bad target, no stdout, spawn failure) is real.
        if (error.stdout) {
            stdout = error.stdout;
        } else {
            throw new Error(`osv-scanner failed: ${error.stderr || error.message}`);
        }
    }

    try {
        return JSON.parse(stdout);
    } catch (parseError) {
        throw new Error(`Could not parse osv-scanner JSON output: ${parseError.message}`);
    }
}

function toRepoPath(p) {
    const relative = path.isAbsolute(p) ? path.relative(process.cwd(), p) : p;
    return relative.split(path.sep).join('/');
}

function readJson(file, what) {
    try {
        return JSON.parse(readFileSync(file, 'utf8'));
    } catch (error) {
        throw new Error(`Could not read ${what} ${file}: ${error.message}`);
    }
}

function findingKey(f) {
    return `${f.packageName}@${f.packageVersion}|${f.id}`;
}

function setOutputs(outputs) {
    if (!process.env.GITHUB_OUTPUT) {
        return;
    }
    const text = Object.entries(outputs).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
    appendFileSync(process.env.GITHUB_OUTPUT, text);
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    checkOsvScannerAvailable();

    const outDir = options.outDir;
    mkdirSync(outDir, { recursive: true });

    // --- exceptions (missing file = none) ---
    let exceptionsList = [];
    if (existsSync(options.exceptions)) {
        const normalized = normalizeExceptions(readJson(options.exceptions, 'exceptions file'));
        exceptionsList = normalized.list;
        normalized.warnings.forEach(w => console.warn(`WARNING: ${w}`));
    } else {
        console.warn(`WARNING: no exceptions file at ${options.exceptions}; proceeding with zero exceptions.`);
    }

    // --- blocking SBOM scope ---
    let bundleAffectedRaw = [];
    let bundleNotAffected = [];
    let unscannable = [];
    if (options.blockingSboms.length > 0) {
        const boms = options.blockingSboms.map(file => {
            if (!existsSync(file)) {
                throw new Error(`Blocking SBOM not found at ${file}.`);
            }
            return readJson(file, 'SBOM');
        });
        const merged = mergeSboms(boms);
        unscannable = merged.unscannable;
        if (unscannable.length > 0) {
            console.warn(`WARNING: ${unscannable.length} component(s) have no usable purl and cannot be scanned: ` +
                unscannable.map(c => `${c.name}${c.version ? `@${c.version}` : ''}`).join(', '));
        }
        // osv-scanner recognises SBOMs by file name, hence the .cdx.json suffix.
        const mergedPath = path.join(outDir, 'sbom-blocking-merged.cdx.json');
        writeFileSync(mergedPath, JSON.stringify(merged.sbom, null, 2));
        console.log(`Scanning ${options.blockingSboms.length} blocking SBOM(s): ${merged.unique} unique component(s) (${merged.total} before dedupe)...`);

        const sarifLocation = options.sarifLocation ||
            (existsSync('package.json') ? 'package.json' : options.blockingSboms[0]);
        if (merged.unique === 0) {
            console.warn('WARNING: the blocking SBOM(s) contain no scannable component; nothing to check.');
        } else {
            const raw = runOsvScanner({ sbomPath: mergedPath });
            const parsed = parseOsvScanOutput(raw, { scope: 'bundle', sourcePath: toRepoPath(sarifLocation) });
            ({ affected: bundleAffectedRaw, notAffected: bundleNotAffected } = partitionByAffected(parsed));
        }
    }

    // --- lockfile scope (blocking or reporting) ---
    let lockfileAffectedRaw = [];
    let lockfileNotAffected = [];
    if (options.lockfile) {
        if (existsSync(options.lockfile)) {
            console.log(`Scanning ${options.lockfile} (${options.blockingLockfile ? 'blocking' : 'reporting only'})...`);
            const raw = runOsvScanner({ lockfilePath: options.lockfile });
            const parsed = parseOsvScanOutput(raw, { scope: 'lockfile', sourcePath: toRepoPath(options.lockfile) });
            ({ affected: lockfileAffectedRaw, notAffected: lockfileNotAffected } = partitionByAffected(parsed));
        } else if (options.blockingLockfile) {
            throw new Error(`Blocking lockfile not found at ${options.lockfile}.`);
        } else {
            console.warn(`WARNING: no lockfile found at ${options.lockfile}, skipping lockfile scope.`);
        }
    }

    // --- enrichment: only findings that count (not-affected ones are
    // reported as-is, unenriched) ---
    const allAffected = [...bundleAffectedRaw, ...lockfileAffectedRaw];
    const allCveIds = [...new Set(allAffected.flatMap(f => f.cveIds))];
    console.log(`Enriching ${allCveIds.length} CVE id(s) with EPSS and CISA KEV${options.offline ? ' (skipped: --offline)' : ''}...`);
    const [epssByCve, kevIds] = await Promise.all([
        fetchEpss(allCveIds, { offline: options.offline }),
        fetchKev({ offline: options.offline })
    ]);
    const bundleFindings = enrichFindings(bundleAffectedRaw, { epssByCve, kevIds });
    const lockfileFindings = enrichFindings(lockfileAffectedRaw, { epssByCve, kevIds });

    // --- gate ---
    // Blocking scope: the SBOM scope, plus the lockfile when it is
    // blocking (findings already in the SBOM scope are not counted twice).
    let blockingInput = bundleFindings;
    let blockingNotAffected = bundleNotAffected;
    let reporting = null;
    if (options.blockingLockfile) {
        const seen = new Set(bundleFindings.map(findingKey));
        blockingInput = [...bundleFindings, ...lockfileFindings.filter(f => !seen.has(findingKey(f)))];
        blockingNotAffected = [...bundleNotAffected, ...lockfileNotAffected];
    } else if (options.lockfile && existsSync(options.lockfile)) {
        // Reporting only: never blocks, same function for one source of truth
        // on severity buckets.
        reporting = {
            ...evaluateGate(lockfileFindings, [], { minSeverity: options.minSeverity, blocking: false }),
            findings: lockfileFindings,
            notAffected: lockfileNotAffected
        };
    }
    const gate = evaluateGate(blockingInput, exceptionsList, { minSeverity: options.minSeverity, blocking: true });
    const blockingScopes = [
        ...(options.blockingSboms.length > 0 ? ['bundle'] : []),
        ...(options.blockingLockfile ? ['lockfile'] : [])
    ];
    const blockingTitle = blockingScopes.map(s => (s === 'bundle' ? 'SBOM scope' : 'Lockfile scope')).join(' and ');

    // --- console report ---
    console.log(formatTable('Blocking scope - blocking findings', gate.blockingFindings));
    console.log(formatTable('Blocking scope - exempted findings (valid exception on file)', gate.exemptedFindings));
    const na = formatNotAffected('Blocking scope - excluded findings', blockingNotAffected);
    if (na) {
        console.log(na);
    }
    if (reporting) {
        console.log(formatTable('Lockfile scope - all findings (reporting only)', reporting.nonBlockingFindings));
        const lna = formatNotAffected('Lockfile scope - excluded findings', reporting.notAffected);
        if (lna) {
            console.log(lna);
        }
    }
    if (gate.expiredExceptions.length > 0) {
        console.log(`\n${gate.expiredExceptions.length} expired exception(s) in ${options.exceptions}:`);
        for (const e of gate.expiredExceptions) {
            console.log(`   - ${e.id} (${e.package || 'any package'}) expired ${e.expires} - remove or renew it.`);
        }
    }
    if (gate.unusedExceptions.length > 0) {
        console.log(`\nWARNING: ${gate.unusedExceptions.length} unused exception(s) in ${options.exceptions} (no matching finding this run):`);
        for (const e of gate.unusedExceptions) {
            console.log(`   - ${e.id} (${e.package || 'any package'})`);
        }
    }

    // --- reports ---
    // Not-affected findings are deliberately excluded from SARIF: they are
    // not real code-scanning results, just transparency (see
    // scan-report.json and scan-summary.md).
    const sarif = buildSarif([...blockingInput, ...(reporting ? reporting.findings : [])], {
        toolName: 'dependency-scan',
        toolVersion: SCANNER_VERSION,
        lockfilePath: toRepoPath(options.lockfile || 'package-lock.json')
    });
    const sarifPath = path.join(outDir, 'results.sarif');
    writeFileSync(sarifPath, JSON.stringify(sarif, null, 2));

    const reportPath = path.join(outDir, 'scan-report.json');
    const { findings: _reportingFindings, ...reportingForJson } = reporting || {};
    writeFileSync(reportPath, JSON.stringify({
        generatedAt: new Date().toISOString(),
        minSeverity: options.minSeverity,
        blockingScopes,
        unscannable,
        blocking: { ...gate, notAffected: blockingNotAffected },
        reporting: reporting ? { ...reportingForJson, notAffected: reporting.notAffected } : null
    }, null, 2));

    const markdown = buildMarkdownSummary({
        blockingTitle, gate, notAffected: blockingNotAffected, reporting, unscannable,
        exceptions: { path: options.exceptions, list: exceptionsList }
    });
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
    }
    writeFileSync(path.join(outDir, 'scan-summary.md'), markdown);

    console.log(`\nSARIF:   ${sarifPath}`);
    console.log(`JSON:    ${reportPath}`);
    console.log(`Summary: ${path.join(outDir, 'scan-summary.md')}`);

    setOutputs({
        'gate-outcome': gate.pass ? 'pass' : 'fail',
        'blocking-count': gate.blockingFindings.length,
        'report-path': reportPath,
        'sarif-path': sarifPath
    });

    if (!gate.pass) {
        console.log('\nVulnerability gate FAILED.');
        process.exit(options.exitZero ? 0 : 1);
    }
    console.log('\nVulnerability gate passed.');
}

main().catch(error => {
    console.error(`ERROR: ${error.message}`);
    process.exit(2);
});
