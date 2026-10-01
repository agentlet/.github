# agentlet/.github

Shared community health files and reusable automation for the agentlet organization.

## Actions

| Action | Purpose |
|---|---|
| [`actions/dependency-scan`](actions/dependency-scan/README.md) | Dependency vulnerability scan with a blocking gate, SARIF upload, expiring exceptions and an optional tracking issue. |
| [`actions/sbom-from-esbuild`](actions/sbom-from-esbuild/README.md) | CycloneDX SBOM of what an esbuild bundle ships, from esbuild metafiles. |

Use them from any workflow by pinning a tag:

```yaml
- uses: agentlet/.github/actions/dependency-scan@dependency-scan-v1
  with:
    blocking-lockfile: 'true'
```

## Development

The actions have no npm dependencies. Run the tests with:

```bash
node --test
```

CI (`.github/workflows/ci.yml`) runs the tests on several Node.js versions, lints the workflows with actionlint, and self-tests both actions against the fixtures in `test-fixtures/`.

`profile/README.md` is the organization profile shown on github.com/agentlet.
