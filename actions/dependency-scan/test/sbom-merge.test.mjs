import { describe, test } from 'node:test';
import { expect } from '../testlib/expect.mjs';
import { mergeSboms, isScannable } from '../lib/sbom-merge.mjs';

const comp = (name, version, extra = {}) => ({ type: 'library', name, version, purl: `pkg:npm/${name}@${version}`, ...extra });
const bom = (...components) => ({ bomFormat: 'CycloneDX', components });

describe('mergeSboms', () => {
    test('unions components and dedupes by purl', () => {
        const { sbom, total, unique } = mergeSboms([
            bom(comp('xlsx', '0.18.5'), comp('ws', '8.18.3')),
            bom(comp('xlsx', '0.18.5'), comp('ms', '2.1.3'))
        ]);
        expect(total).toBe(4);
        expect(unique).toBe(3);
        expect(sbom.components.map(c => c.purl)).toEqual([
            'pkg:npm/ms@2.1.3', 'pkg:npm/ws@8.18.3', 'pkg:npm/xlsx@0.18.5'
        ]);
    });

    test('keeps two versions of the same package apart', () => {
        const { unique } = mergeSboms([bom(comp('ws', '7.4.0')), bom(comp('ws', '8.18.3'))]);
        expect(unique).toBe(2);
    });

    test('produces a CycloneDX 1.5 document', () => {
        const { sbom } = mergeSboms([bom(comp('ms', '2.1.3'))], { timestamp: '2026-01-01T00:00:00.000Z' });
        expect(sbom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1 });
        expect(sbom.metadata.timestamp).toBe('2026-01-01T00:00:00.000Z');
    });

    test('flattens nested components', () => {
        const { sbom } = mergeSboms([bom(comp('a', '1.0.0', { components: [comp('b', '2.0.0')] }))]);
        expect(sbom.components.map(c => c.name)).toEqual(['a', 'b']);
        expect(sbom.components[0].components).toBeUndefined();
    });

    test('reports components without a usable purl as unscannable instead of dropping them silently', () => {
        const { sbom, unscannable } = mergeSboms([
            bom(
                comp('chart.js', '4.5.1'),
                { type: 'library', name: 'swiper-cdnjs', version: '11.0.0' },
                { type: 'library', name: 'swiper-cdnjs', version: '11.0.0' },
                { type: 'library', name: 'versionless', purl: 'pkg:npm/versionless' }
            )
        ]);
        expect(sbom.components.map(c => c.name)).toEqual(['chart.js']);
        expect(unscannable).toEqual([
            { name: 'swiper-cdnjs', version: '11.0.0', purl: '' },
            { name: 'versionless', version: '', purl: 'pkg:npm/versionless' }
        ]);
    });

    test('tolerates SBOMs with no components and junk entries', () => {
        const result = mergeSboms([{}, null, { components: [null, 'x'] }]);
        expect(result.unique).toBe(0);
        expect(result.unscannable).toEqual([]);
    });
});

describe('isScannable', () => {
    test('needs a purl with a version', () => {
        expect(isScannable({ purl: 'pkg:npm/%40scope/pkg@1.2.3' })).toBe(true);
        expect(isScannable({ purl: 'pkg:npm/pkg' })).toBe(false);
        expect(isScannable({})).toBe(false);
    });
});
