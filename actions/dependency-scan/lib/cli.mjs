/**
 * Argument parsing and small input helpers for bin/scan.mjs. Pure: no
 * process access, so it can be unit tested (test/cli.test.mjs).
 */

import { SEVERITY_ORDER } from './gate-core.mjs';

/**
 * Split a "newline and/or comma separated" list (the format the action
 * inputs use) into trimmed, non-empty entries.
 */
function splitList(value) {
    return String(value ?? '')
        .split(/[\n,]/)
        .map(entry => entry.trim())
        .filter(Boolean);
}

function parseBoolean(name, value) {
    const normalised = String(value).trim().toLowerCase();
    if (['', 'true', '1', 'yes'].includes(normalised)) {
        return true;
    }
    if (['false', '0', 'no'].includes(normalised)) {
        return false;
    }
    throw new Error(`Invalid value for ${name}: "${value}". Use true or false.`);
}

const VALUE_FLAGS = new Set([
    '--min-severity', '--blocking-sbom', '--lockfile', '--exceptions', '--out-dir', '--sarif-location'
]);
const BOOLEAN_FLAGS = new Set(['--blocking-lockfile', '--offline', '--exit-zero']);

/**
 * Parse CLI arguments. Both `--flag=value` and `--flag value` are
 * accepted for value flags (use the `=` form to pass an empty value, e.g.
 * `--lockfile=` to skip the reporting scope). `--blocking-sbom` may be
 * repeated and each value may itself be a newline/comma separated list.
 * Boolean flags may be bare (`--offline`) or explicit (`--offline=false`).
 * Unknown flags are an error so a typo never silently weakens the gate.
 */
function parseArgs(argv) {
    const options = {
        minSeverity: 'high',
        blockingSboms: [],
        blockingLockfile: false,
        lockfile: 'package-lock.json',
        exceptions: 'security/vulnerability-exceptions.json',
        outDir: 'reports/security',
        sarifLocation: '',
        offline: false,
        exitZero: false
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        const eq = arg.indexOf('=');
        const flag = eq === -1 ? arg : arg.slice(0, eq);
        let value = eq === -1 ? undefined : arg.slice(eq + 1);

        if (BOOLEAN_FLAGS.has(flag)) {
            const parsed = value === undefined ? true : parseBoolean(flag, value);
            if (flag === '--blocking-lockfile') {
                options.blockingLockfile = parsed;
            } else if (flag === '--offline') {
                options.offline = parsed;
            } else {
                options.exitZero = parsed;
            }
            continue;
        }

        if (!VALUE_FLAGS.has(flag)) {
            throw new Error(`Unknown argument: ${arg}`);
        }
        if (value === undefined) {
            i += 1;
            if (i >= argv.length) {
                throw new Error(`Missing value for ${flag}`);
            }
            value = argv[i];
        }

        switch (flag) {
            case '--min-severity': options.minSeverity = value; break;
            case '--blocking-sbom': options.blockingSboms.push(...splitList(value)); break;
            case '--lockfile': options.lockfile = value.trim(); break;
            case '--exceptions': options.exceptions = value.trim(); break;
            case '--out-dir': options.outDir = value.trim(); break;
            case '--sarif-location': options.sarifLocation = value.trim(); break;
        }
    }

    if (!SEVERITY_ORDER.includes(options.minSeverity)) {
        throw new Error(`Invalid --min-severity=${options.minSeverity}. Must be one of ${SEVERITY_ORDER.join(', ')}.`);
    }
    if (!options.blockingLockfile && options.blockingSboms.length === 0) {
        throw new Error('Nothing is blocking: pass --blocking-sbom=<path> (repeatable) and/or --blocking-lockfile.');
    }
    if (options.blockingLockfile && !options.lockfile) {
        throw new Error('--blocking-lockfile needs a lockfile: --lockfile must not be empty.');
    }
    if (!options.outDir) {
        throw new Error('--out-dir must not be empty.');
    }
    return options;
}

/**
 * Accepts either `{ "exceptions": [...] }` or a bare array. Returns the
 * entries plus human-readable warnings for entries that break the review
 * policy (missing owner/reason/expiry); malformed entries (no id) throw.
 */
function normalizeExceptions(parsed) {
    const list = Array.isArray(parsed) ? parsed : (parsed?.exceptions ?? []);
    if (!Array.isArray(list)) {
        throw new Error('Exceptions file must be an array or an object with an "exceptions" array.');
    }
    const warnings = [];
    list.forEach((entry, index) => {
        if (!entry || typeof entry.id !== 'string' || entry.id === '') {
            throw new Error(`Exceptions entry #${index + 1} has no "id".`);
        }
        for (const field of ['reason', 'expires', 'owner']) {
            if (!entry[field]) {
                warnings.push(`Exception ${entry.id} has no "${field}"; the review policy asks for owner, reason and expiry.`);
            }
        }
        if (entry.expires && !/^\d{4}-\d{2}-\d{2}$/.test(entry.expires)) {
            warnings.push(`Exception ${entry.id} has an "expires" that is not YYYY-MM-DD: ${entry.expires}`);
        }
    });
    return { list, warnings };
}

export { splitList, parseArgs, normalizeExceptions };
