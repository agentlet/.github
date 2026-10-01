# sbom-from-esbuild

A composite GitHub Action that builds a CycloneDX 1.5 SBOM of what an esbuild bundle ships, from one or more esbuild metafiles. Feed the result to the [dependency-scan](../dependency-scan/README.md) action as its blocking scope.

## Why

esbuild inlines every bundled dependency into one file, so a filesystem or container scanner finds no components in `dist/`. `package-lock.json` lists everything installed, including build tooling that never ships. The esbuild metafile (`metafile: true`) lists every source file that went into a bundle, including everything under `node_modules/`, which makes it the reliable inventory of what ships.

For each `node_modules` input the action finds the nearest owning package directory (handling scoped and nested `node_modules`, so two versions of one package are kept apart), reads its `package.json`, and emits a component with a purl and a license.

## Usage

Make your build write the metafile to disk, for example:

```js
import { build } from 'esbuild';
import { writeFileSync } from 'node:fs';

const result = await build({ entryPoints: ['src/index.ts'], bundle: true, outfile: 'dist/index.js', metafile: true });
writeFileSync('dist/index.meta.json', JSON.stringify(result.metafile));
```

Then, after the build:

```yaml
- name: Build the shipped-inventory SBOM
  id: sbom
  uses: agentlet/.github/actions/sbom-from-esbuild@dependency-scan-v1
  with:
    metafiles: |
      dist/index.meta.json
      dist/extension.meta.json

- uses: agentlet/.github/actions/dependency-scan@dependency-scan-v1
  with:
    blocking-sbom: ${{ steps.sbom.outputs.sbom-path }}
```

The action needs Node.js 20 or newer on the runner (preinstalled on `ubuntu-latest`). Pin it to the same tag as `dependency-scan`: both are versioned together, and this action runs the shared script from the `dependency-scan` directory of the same checkout.

## Inputs

| Input | Default | Description |
|---|---|---|
| `metafiles` | required | Newline or comma separated list of esbuild metafile paths. |
| `root` | `.` | Directory that holds `node_modules`. Metafile input paths are resolved against it. |
| `name` | root `package.json` name | `metadata.component` name. |
| `version` | root `package.json` version | `metadata.component` version. |
| `output` | `reports/security/sbom-bundle.cdx.json` | Where to write the SBOM. |

The action fails if a metafile does not exist, or if the component name and version cannot be determined from the inputs or from `<root>/package.json`. A `node_modules` directory with no readable `package.json` is skipped with a warning.

## Outputs

| Output | Description |
|---|---|
| `sbom-path` | Path of the generated SBOM (the value of `output`). |

## Running locally

```bash
node actions/dependency-scan/bin/sbom-from-esbuild-metafile.mjs --root=. --out=reports/security/sbom-bundle.cdx.json dist/index.meta.json
```

Metafile paths may be given as positional arguments or with `--metafile=<path>` (repeatable, newline or comma lists accepted). `--name` and `--version` override the root `package.json`.

## Tests

```bash
node --test
```
