#!/usr/bin/env node
/**
 * Builds a CycloneDX 1.5 SBOM of what an esbuild bundle actually SHIPS,
 * from one or more esbuild metafiles (`metafile: true`, then write
 * `result.metafile` to disk).
 *
 * Why this exists instead of a filesystem/container scanner: esbuild
 * inlines every bundled dependency into a single file, so a scanner finds
 * zero components in dist/. The metafile is the only reliable inventory of
 * what a bundle contains.
 *
 * Usage:
 *   node sbom-from-esbuild-metafile.mjs [options] <metafile> [<metafile>...]
 *     --root=<dir>      directory the metafile input paths are relative to
 *                       and that holds node_modules (default: .)
 *     --name=<name>     metadata.component name (default: root package.json)
 *     --version=<ver>   metadata.component version (default: root package.json)
 *     --out=<path>      default: reports/security/sbom-bundle.cdx.json
 *
 * When $GITHUB_OUTPUT is set, writes sbom-path to it.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { collectPackageDirs, dedupePackages, buildSbom } from '../lib/sbom-core.mjs';
import { parseSbomArgs, resolvePackage } from '../lib/esbuild-sbom.mjs';

function main() {
    const options = parseSbomArgs(process.argv.slice(2));
    const root = path.resolve(options.root);

    const metafiles = options.metafiles.map(file => {
        const resolved = path.resolve(file);
        if (!existsSync(resolved)) {
            throw new Error(`esbuild metafile not found: ${file}. Build with metafile: true and write result.metafile to disk first.`);
        }
        return JSON.parse(readFileSync(resolved, 'utf8'));
    });

    const packageDirs = collectPackageDirs(metafiles);
    const packages = dedupePackages(
        packageDirs.map(dir => resolvePackage(root, dir, msg => console.warn(`WARNING: ${msg}`))).filter(Boolean)
    );

    let rootPkg = {};
    const rootPkgPath = path.join(root, 'package.json');
    if (existsSync(rootPkgPath)) {
        rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8'));
    }
    const name = options.name || rootPkg.name;
    const version = options.version || rootPkg.version;
    if (!name || !version) {
        throw new Error(`Cannot determine metadata.component: pass --name and --version, or provide ${rootPkgPath} with both.`);
    }

    const sbom = buildSbom({
        rootComponent: { name, version, description: options.name ? undefined : rootPkg.description },
        packages
    });

    const out = path.resolve(options.out);
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, JSON.stringify(sbom, null, 2));

    console.log(`Shipped-inventory SBOM: ${packages.length} bundled package(s) across ${metafiles.length} metafile(s)`);
    for (const pkg of packages.slice().sort((a, b) => a.name.localeCompare(b.name))) {
        console.log(`   - ${pkg.name}@${pkg.version}${pkg.license ? ` (${pkg.license})` : ''}`);
    }
    console.log(`Written to ${options.out}`);

    if (process.env.GITHUB_OUTPUT) {
        appendFileSync(process.env.GITHUB_OUTPUT, `sbom-path=${options.out}\n`);
    }
}

try {
    main();
} catch (error) {
    console.error(`ERROR: ${error.message}`);
    process.exit(2);
}
