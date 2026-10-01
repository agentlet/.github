/**
 * Tiny `expect` shim over node:assert, covering just the matchers the
 * ported test suites use, so the original test bodies read the same and
 * the repo stays free of any test-framework dependency.
 */

import assert from 'node:assert/strict';

function isObject(value) {
    return value !== null && typeof value === 'object';
}

function subsetOf(actual, expected) {
    if (!isObject(expected)) {
        return Object.is(actual, expected);
    }
    if (!isObject(actual)) {
        return false;
    }
    if (Array.isArray(expected)) {
        return Array.isArray(actual) && actual.length === expected.length &&
            expected.every((item, i) => subsetOf(actual[i], item));
    }
    return Object.keys(expected).every(key => subsetOf(actual[key], expected[key]));
}

function expect(actual) {
    return {
        toBe: expected => assert.strictEqual(actual, expected),
        toEqual: expected => assert.deepStrictEqual(actual, expected),
        toBeNull: () => assert.strictEqual(actual, null),
        toBeUndefined: () => assert.strictEqual(actual, undefined),
        toBeTruthy: () => assert.ok(actual),
        toHaveLength: length => assert.strictEqual(actual.length, length),
        toBeGreaterThan: n => assert.ok(actual > n, `expected ${actual} > ${n}`),
        toBeLessThan: n => assert.ok(actual < n, `expected ${actual} < ${n}`),
        toMatch: pattern => assert.match(actual, pattern),
        toContain: item => assert.ok(
            typeof actual === 'string' ? actual.includes(item) : actual.includes(item),
            `expected ${JSON.stringify(actual)} to contain ${JSON.stringify(item)}`
        ),
        toMatchObject: expected => assert.ok(
            subsetOf(actual, expected),
            `expected ${JSON.stringify(actual)} to match ${JSON.stringify(expected)}`
        )
    };
}

export { expect };
