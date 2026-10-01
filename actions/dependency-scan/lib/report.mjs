/**
 * Console tables and the markdown job summary. Pure string builders.
 */

const pct = value => `${(value * 100).toFixed(1)}%`;

function formatTable(title, findings) {
    const lines = [`\n${title} (${findings.length} finding${findings.length === 1 ? '' : 's'})`];
    if (findings.length === 0) {
        lines.push('  (none)');
        return lines.join('\n');
    }
    for (const finding of findings) {
        const fixed = finding.fixedVersion ? `fix: ${finding.fixedVersion}` : 'no fix yet';
        const epss = finding.epss === null || finding.epss === undefined ? 'epss: unknown' : `epss: ${pct(finding.epss)}`;
        lines.push(`  ${finding.severity.padEnd(8)} ${finding.packageName}@${finding.packageVersion}  ${finding.id}  (${fixed}, ${epss}${finding.kev ? ', KEV' : ''})`);
    }
    return lines.join('\n');
}

/**
 * Findings osv-scanner reported but that the advisory's known-affected
 * range rules out: never gated and never in SARIF, but listed so a
 * reviewer can see why a CVE in osv-scanner's own output has no finding.
 */
function formatNotAffected(title, findings) {
    if (findings.length === 0) {
        return '';
    }
    const lines = [`\n${title} (${findings.length} finding${findings.length === 1 ? '' : 's'}, not affected per advisory range)`];
    for (const finding of findings) {
        lines.push(`  ${finding.packageName}@${finding.packageVersion}  ${finding.id}  - ${finding.notAffectedReason || "installed version is outside the advisory's affected range"}`);
    }
    return lines.join('\n');
}

function buildMarkdownSummary({ blockingTitle, gate, notAffected, reporting, unscannable = [], exceptions }) {
    const lines = ['# Dependency vulnerability scan', ''];

    lines.push(`## ${blockingTitle} (blocking)`, '');
    lines.push(gate.pass ? 'Gate passed.' : 'Gate failed.', '');
    if (gate.blockingFindings.length > 0) {
        lines.push('| Severity | Package | Advisory | Fixed | EPSS | KEV |');
        lines.push('|---|---|---|---|---|---|');
        for (const f of gate.blockingFindings) {
            const epss = f.epss === null || f.epss === undefined ? 'unknown' : pct(f.epss);
            const advisory = f.references[0] ? `[${f.id}](${f.references[0]})` : f.id;
            lines.push(`| ${f.severity} | ${f.packageName}@${f.packageVersion} | ${advisory} | ${f.fixedVersion || 'none'} | ${epss} | ${f.kev ? 'yes' : 'no'} |`);
        }
        lines.push('');
    }
    if (gate.exemptedFindings.length > 0) {
        lines.push('**Exempted by a valid exception:**');
        for (const f of gate.exemptedFindings) {
            lines.push(`- \`${f.packageName}@${f.packageVersion}\` ${f.id}, exception expires ${f.exception.expires || 'never'}`);
        }
        lines.push('');
    }
    if (gate.expiredExceptions.length > 0) {
        lines.push('**Expired exceptions (fail the gate until removed or renewed):**');
        for (const e of gate.expiredExceptions) {
            lines.push(`- \`${e.id}\` (${e.package || 'any package'}), expired ${e.expires}`);
        }
        lines.push('');
    }
    if (gate.unusedExceptions.length > 0) {
        lines.push('**Unused exceptions (no matching finding this run):**');
        for (const e of gate.unusedExceptions) {
            lines.push(`- \`${e.id}\` (${e.package || 'any package'})`);
        }
        lines.push('');
    }
    if (notAffected.length > 0) {
        lines.push('**Not affected per advisory range** (osv-scanner reported these, but the installed version ' +
            "is outside the advisory's known-affected range, so they are excluded from the gate and SARIF):");
        for (const f of notAffected) {
            lines.push(`- \`${f.packageName}@${f.packageVersion}\` ${f.id}: ${f.notAffectedReason || 'outside affected range'}`);
        }
        lines.push('');
    }

    if (unscannable.length > 0) {
        lines.push(`**Not scannable** (${unscannable.length} component(s) in the blocking SBOM have no usable purl, so they were NOT checked against advisories):`);
        for (const c of unscannable) {
            lines.push(`- \`${c.name}${c.version ? `@${c.version}` : ''}\``);
        }
        lines.push('');
    }

    if (reporting) {
        lines.push('## Lockfile scope (reporting only, never blocks)', '');
        lines.push(`${reporting.findings.length} finding(s) across the full install tree (build tooling and dev dependencies included).`);
        if (reporting.notAffected.length > 0) {
            lines.push(`${reporting.notAffected.length} additional finding(s) excluded as not affected per advisory range.`);
        }
        lines.push('');
    }
    lines.push(`_Exceptions file: \`${exceptions.path}\` (${exceptions.list.length} entr${exceptions.list.length === 1 ? 'y' : 'ies'})._`);
    return lines.join('\n');
}

export { formatTable, formatNotAffected, buildMarkdownSummary };
