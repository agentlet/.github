# dependency-scan

A composite GitHub Action that scans dependencies for known vulnerabilities and applies a blocking gate. It is the shared version of the scanner that runs in agentlet-core, with every path configurable.

What it does, in order:

1. Installs a pinned osv-scanner release binary and verifies it against the release's `SHA256SUMS` file.
2. Scans the blocking scope (one or more CycloneDX SBOMs, and/or the whole lockfile) and, optionally, the lockfile as a reporting scope.
3. Enriches findings with EPSS (exploitation probability) and the CISA Known Exploited Vulnerabilities (KEV) catalog. A network failure here degrades to "unknown" with a warning, never to a failed scan.
4. Applies the gate and the expiring exceptions file.
5. Writes SARIF 2.1.0, a JSON report and a markdown job summary, uploads the SARIF to code scanning and the reports as an artifact.
6. Optionally opens or updates one tracking issue, then fails the job if the gate failed.

The action has no npm dependencies: it only needs Node.js 20 or newer on the runner (preinstalled on `ubuntu-latest`; add `actions/setup-node` before it otherwise) and runs on Linux x64 runners only.

## Scopes

| Scope | Input | Blocks? | Use for |
|---|---|---|---|
| Blocking SBOM | `blocking-sbom` | Yes | What you ship: the packages inside a bundle, or the libraries a page loads. |
| Blocking lockfile | `blocking-lockfile: true` | Yes | Repos where everything runs on a developer machine, so the whole install tree matters. |
| Reporting lockfile | `lockfile` | No | Visibility into build tooling and dev dependencies. Shown in SARIF and the summary, never fails the gate. |

Several SBOMs can be given, as newline or comma separated paths. They are merged and deduplicated by purl before scanning. Components without a usable purl (for example a script loaded from a CDN that was only recorded by name) cannot be matched against advisories. They are not scanned, a warning is printed, and they are listed under "Not scannable" in the job summary and in `scan-report.json`.

## Gate rule

A finding in the blocking scope fails the gate when:

- it is critical or high severity (or at least `min-severity`) **and** a fixed version is known, **or**
- it is listed in the CISA KEV catalog, regardless of severity,

unless a valid, unexpired entry in the exceptions file covers it. An expired exception stops matching and fails the gate on its own, until it is renewed or removed. An unused exception only produces a warning. The reporting lockfile scope never blocks.

Details that matter in practice:

- Severity comes from the advisory's `database_specific.severity` label, falling back to a CVSS v3 base score computed from the vector.
- The fixed version is taken from the OSV range that contains the installed version, so a multi-branch advisory (one fix per major version) reports the right fix for each install.
- For advisories whose real fix was never published to the registry, the advisory's `last_known_affected_version_range` is honoured: an installed version outside that range is reported as "not affected per advisory range", excluded from the gate and from SARIF, and listed in the report for transparency.

## Inputs

| Input | Default | Description |
|---|---|---|
| `blocking-sbom` | empty | Path, or newline/comma separated list of paths, to CycloneDX SBOM files that form the blocking scope. Required unless `blocking-lockfile` is `true`. |
| `blocking-lockfile` | `false` | When `true` the whole lockfile is the blocking scope. |
| `lockfile` | `package-lock.json` | Lockfile to scan. Reporting only unless `blocking-lockfile` is `true`. An empty string skips it (for repos with no lockfile). |
| `exceptions-file` | `security/vulnerability-exceptions.json` | Expiring exceptions. A missing file means no exceptions. |
| `report-dir` | `reports/security` | Output directory, relative to the workspace. |
| `min-severity` | `high` | Minimum severity that can block: `low`, `medium`, `high` or `critical`. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Skipped on fork pull requests and when no SARIF was produced. |
| `sarif-category` | `dependency-vulnerabilities` | Code scanning category. |
| `artifact-name` | `dependency-scan-reports` | Name of the reports artifact. Must be unique per workflow run: set it when you use the action more than once. |
| `fail-on-gate` | `true` | Fail the job when the gate fails. |
| `issue-on-failure` | `false` | When `true` and the gate fails, open or update one issue labelled `security`. The job needs `issues: write`. |
| `issue-title` | `Dependency scan: blocking vulnerability` | Title of the tracking issue, also its dedupe key: an open `security` issue with exactly this title is commented on instead of a new one being created. |
| `osv-scanner-version` | `2.6.0` | Pinned osv-scanner release. |
| `github-token` | `${{ github.token }}` | Token for the issue step. |

## Outputs

| Output | Description |
|---|---|
| `gate-outcome` | `pass` or `fail`. Set even when `fail-on-gate` is `false`. |
| `blocking-count` | Number of blocking findings after exceptions. An expired exception fails the gate without adding to this count. |
| `report-path` | Path of `scan-report.json`. |
| `sarif-path` | Path of `results.sarif`. |

Files written to `report-dir`: `results.sarif`, `scan-report.json`, `scan-summary.md` and, when a blocking SBOM is used, `sbom-blocking-merged.cdx.json` (the merged input actually scanned). The SARIF fingerprint key is `dependencyVulnerability/v1` (package, advisory and scope), because every result points at line 1 of its file and the default line-hash fingerprint cannot tell them apart.

## Permissions

The calling job needs:

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload; not needed with upload-sarif: false
  issues: write            # only with issue-on-failure: true
```

The calling workflow must check out the repository first. SARIF upload to code scanning needs code scanning to be available for the repository; set `upload-sarif: 'false'` where it is not.

## Exceptions file

```json
{
  "exceptions": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "package": "some-package",
      "reason": "No upstream fix yet and the affected code path is not reachable from our build",
      "expires": "2026-12-31",
      "owner": "github-handle"
    }
  ]
}
```

- `id`: a GHSA or CVE id. It matches a finding on any of its aliases, so either works.
- `package`: optional. When present the exception only applies to that package name.
- `reason`: required. Why the risk is accepted.
- `expires`: required, `YYYY-MM-DD`. Once past, the entry fails the gate until renewed or removed.
- `owner`: required by policy. The person who follows up.

A bare array of entries is accepted as well. A missing `reason`, `expires` or `owner` is reported as a warning.

Review policy: an exception is a deliberate, time-boxed decision to accept a known risk, for example when no upstream fix exists and the affected code path cannot be reached. It names a real owner and a realistic expiry, never a far-future date used to silence the gate. Exception changes are reviewed like code, in a pull request. Unused exceptions show up as warnings so stale entries get removed.

## Example workflows

All examples pin the action by tag. See [Versioning](#versioning).

### a) Bundled library or site

Build with esbuild, turn the metafile into an SBOM of what the bundle ships, and make that the blocking scope. The lockfile is reported but does not block.

```yaml
name: Security

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]
  schedule:
    - cron: '17 3 * * *'
  workflow_dispatch: {}

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      security-events: write
      issues: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22.x
          cache: npm
      - run: npm ci
      - run: npm run build   # must write esbuild metafiles, for example dist/meta/*.meta.json

      - name: Build the shipped-inventory SBOM
        id: sbom
        uses: agentlet/.github/actions/sbom-from-esbuild@dependency-scan-v1
        with:
          metafiles: |
            dist/meta/index.meta.json
            dist/meta/bookmarklet.meta.json

      - name: Scan
        uses: agentlet/.github/actions/dependency-scan@dependency-scan-v1
        with:
          blocking-sbom: ${{ steps.sbom.outputs.sbom-path }}
          issue-on-failure: ${{ github.event_name == 'schedule' }}
          issue-title: 'Nightly scan: main has a blocking vulnerability'
```

### b) Local tooling repository

Everything runs on a developer machine, so the whole lockfile is the blocking scope. There is no build step and no SBOM.

```yaml
name: Security

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]
  schedule:
    - cron: '41 4 * * *'
  workflow_dispatch: {}

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      security-events: write
      issues: write
    steps:
      - uses: actions/checkout@v7
      - uses: agentlet/.github/actions/dependency-scan@dependency-scan-v1
        with:
          blocking-lockfile: 'true'
          issue-on-failure: ${{ github.event_name == 'schedule' }}
          issue-title: 'Nightly scan: dependencies have a blocking vulnerability'
```

### c) Static site with CDN scripts

The repository has no lockfile. Its own script writes a CycloneDX SBOM listing the libraries the pages load. Components need a purl such as `pkg:npm/chart.js@4.5.1` to be scannable; components without one are reported as not scannable.

```yaml
name: Security

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]
  schedule:
    - cron: '23 5 * * *'
  workflow_dispatch: {}

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      security-events: write
      issues: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22.x

      - name: Generate the CDN SBOM
        run: node scripts/cdn-sbom.mjs   # writes reports/security/sbom-cdn.cdx.json

      - uses: agentlet/.github/actions/dependency-scan@dependency-scan-v1
        with:
          blocking-sbom: reports/security/sbom-cdn.cdx.json
          lockfile: ''
          issue-on-failure: ${{ github.event_name == 'schedule' }}
          issue-title: 'Nightly scan: a CDN library has a blocking vulnerability'
```

### Nightly issue pattern

Pull request and push failures are already visible as failed checks and do not need an issue. The nightly run catches advisories published after a merge, which have no failing check to point at. Set `issue-on-failure: ${{ github.event_name == 'schedule' }}` as above, give `issue-title` a fixed value, and grant `issues: write`. The first failing night opens an issue labelled `security`; later failing nights add a comment with the new summary to the same issue instead of opening duplicates. Close it once the gate is green again.

To scan a published release rather than the current tree, download the release's SBOM asset in an earlier step and pass it as `blocking-sbom` with `lockfile: ''` and its own `issue-title`.

## Running locally

```bash
brew install osv-scanner
node actions/dependency-scan/bin/scan.mjs --blocking-sbom=reports/security/sbom-bundle.cdx.json
node actions/dependency-scan/bin/scan.mjs --blocking-lockfile
```

Options: `--blocking-sbom` (repeatable), `--blocking-lockfile`, `--lockfile`, `--exceptions`, `--out-dir`, `--min-severity`, `--sarif-location`, `--offline` (skip EPSS and KEV), `--exit-zero`. Exit codes: `0` gate passed, `1` gate failed, `2` error. Set `OSV_SCANNER_BIN` to use an osv-scanner that is not on `PATH`.

## Versioning

Callers pin a tag: `agentlet/.github/actions/dependency-scan@<tag>`. The first tag is `dependency-scan-v1`. The `sbom-from-esbuild` action shares its implementation with this one, so pin both to the same tag. Move to a newer tag deliberately and read what changed, since a scanner change can turn a green repository red.

Pinning to a full commit SHA is the strictest option and is recommended for repositories that publish packages.

## Tests

```bash
node --test
```

No dependencies are needed. The CLI tests use a fake osv-scanner in `testlib/` and run offline.
