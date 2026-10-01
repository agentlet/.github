/**
 * Argument parsing and package.json resolution for
 * bin/sbom-from-esbuild-metafile.mjs. Kept apart from the CLI so it can be
 * unit tested (actions/sbom-from-esbuild/test/).
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { splitList } from './cli.mjs';

function parseSbomArgs(argv) {
    const options = { metafiles: [], root: '.', name: '', version: '', out: path.join('reports', 'security', 'sbom-bundle.cdx.json') };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (!arg.startsWith('--')) {
            options.metafiles.push(...splitList(arg));
            continue;
        }
        const eq = arg.indexOf('=');
        const flag = eq === -1 ? arg : arg.slice(0, eq);
        let value = eq === -1 ? undefined : arg.slice(eq + 1);
        if (!['--root', '--name', '--version', '--out', '--metafile'].includes(flag)) {
            throw new Error(`Unknown argument: ${arg}`);
        }
        if (value === undefined) {
            i += 1;
            if (i >= argv.length) {
                throw new Error(`Missing value for ${flag}`);
            }
            value = argv[i];
        }
        if (flag === '--metafile') {
            options.metafiles.push(...splitList(value));
        } else {
            options[flag.slice(2)] = value.trim();
        }
    }
    if (options.metafiles.length === 0) {
        throw new Error('Pass at least one esbuild metafile path (positional or --metafile=<path>).');
    }
    if (!options.out) {
        throw new Error('--out must not be empty.');
    }
    return options;
}

/**
 * Read a package's license from its package.json (string, `{type}` object
 * or legacy `licenses` array).
 */
function licenseOf(pkg) {
    if (typeof pkg.license === 'string') {
        return pkg.license;
    }
    if (pkg.license && pkg.license.type) {
        return pkg.license.type;
    }
    if (Array.isArray(pkg.licenses) && pkg.licenses[0]) {
        return pkg.licenses[0].type;
    }
    return undefined;
}

/**
 * Resolve one bundled package's package.json using the exact node_modules
 * directory the metafile pointed at (handles scoped and nested
 * node_modules, and packages pinned at different versions in different
 * places in the tree). Returns null (and calls `warn`) if it is missing.
 */
function resolvePackage(root, packageDir, warn = console.warn) {
    const packageJsonPath = path.join(root, packageDir, 'package.json');
    if (!existsSync(packageJsonPath)) {
        warn(`Could not find package.json for ${packageDir}, skipping`);
        return null;
    }
    const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
    if (!pkg.name || !pkg.version) {
        warn(`${packageDir}/package.json has no name or version, skipping`);
        return null;
    }
    return { name: pkg.name, version: pkg.version, license: licenseOf(pkg), description: pkg.description };
}

export { parseSbomArgs, licenseOf, resolvePackage };
