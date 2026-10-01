/**
 * A component is scannable when it carries a purl with a version
 * ("pkg:type/name@version"): osv-scanner matches on purls only.
 */
function isScannable(component) {
    return typeof component.purl === 'string' && /^pkg:[^/]+\/.+@.+/.test(component.purl);
}

/**
 * Merge several CycloneDX SBOMs into one component list, deduplicated by
 * purl. Nested `components` are flattened. Components without a usable
 * purl (for example scripts loaded from a CDN that the repo's own script
 * could only record by name) cannot be matched against advisories: they
 * are left out of the merged SBOM and returned in `unscannable` so the
 * caller can warn and list them. Pure; see test/sbom-merge.test.mjs.
 */

function* walkComponents(components) {
    for (const component of components || []) {
        if (!component || typeof component !== 'object') {
            continue;
        }
        yield component;
        yield* walkComponents(component.components);
    }
}

function componentKey(component) {
    if (component.purl) {
        return component.purl;
    }
    return `${component.name || ''}@${component.version || ''}`;
}

function mergeSboms(boms, { timestamp } = {}) {
    const byKey = new Map();
    const unscannableByKey = new Map();
    let total = 0;
    for (const bom of boms) {
        for (const component of walkComponents(bom?.components)) {
            total += 1;
            const key = componentKey(component);
            if (!isScannable(component)) {
                if (!unscannableByKey.has(key)) {
                    unscannableByKey.set(key, {
                        name: component.name || '(unnamed)',
                        version: component.version || '',
                        purl: component.purl || ''
                    });
                }
                continue;
            }
            if (!byKey.has(key)) {
                const { components: _nested, ...flat } = component;
                byKey.set(key, flat);
            }
        }
    }
    const components = [...byKey.values()].sort(
        (a, b) => componentKey(a).localeCompare(componentKey(b))
    );
    return {
        sbom: {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            version: 1,
            metadata: { timestamp: timestamp || new Date().toISOString() },
            components
        },
        total,
        unique: components.length,
        unscannable: [...unscannableByKey.values()]
    };
}

export { mergeSboms, componentKey, isScannable };
