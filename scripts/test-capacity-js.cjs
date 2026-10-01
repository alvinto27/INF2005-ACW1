/* Node built-in tests for pure browser capacity/layout helpers. */
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = readFileSync(
  path.join(__dirname, '..', 'stego_web', 'static', 'capacity.js'),
  'utf8',
);
const window = {};
vm.runInNewContext(source, {window}, {filename: 'capacity.js'});
const {clampStart, evaluateLayout, fitsAtStart, startRange} = window.StegoCapacity;

const results = [
  {lsb_bits: 1, max_start_unit: 20, max_payload_bytes_at_min_start: 10},
  {lsb_bits: 2, max_start_unit: 40, max_payload_bytes_at_min_start: 20},
  {lsb_bits: 3, max_start_unit: 60, max_payload_bytes_at_min_start: 30},
  {lsb_bits: 4, max_start_unit: 80, max_payload_bytes_at_min_start: 40},
  {lsb_bits: 5, max_start_unit: 100, max_payload_bytes_at_min_start: 50},
  {lsb_bits: 6, max_start_unit: 120, max_payload_bytes_at_min_start: 60},
  {lsb_bits: 7, max_start_unit: 140, max_payload_bytes_at_min_start: 70},
  {lsb_bits: 8, max_start_unit: 160, max_payload_bytes_at_min_start: 80},
];

test('returns the legal start range for a fitting LSB', () => {
  assert.deepEqual({...startRange(10, 2, results)}, {min: 10, max: 40});
});

test('returns null when an LSB has no fitting start', () => {
  const nonFitting = results.map(entry => ({...entry, max_start_unit: null}));
  assert.equal(startRange(10, 1, nonFitting), null);
});

test('clamps a start above the range to its maximum', () => {
  assert.equal(clampStart(99, {min: 10, max: 20}), 20);
});

test('clamps a start below the range to its minimum', () => {
  assert.equal(clampStart(3, {min: 10, max: 20}), 10);
});

test('keeps a start inside the range unchanged', () => {
  assert.equal(clampStart(15, {min: 10, max: 20}), 15);
});

test('fits at the latest legal start unit', () => {
  assert.equal(fitsAtStart(20, 10, 20), true);
});

test('does not fit one unit after the latest legal start', () => {
  assert.equal(fitsAtStart(21, 10, 20), false);
});

test('does not fit below the bootstrap span', () => {
  assert.equal(fitsAtStart(9, 10, 20), false);
});

test('suggests the smallest fitting LSB depth', () => {
  const result = evaluateLayout(21, 10, 1, results);
  assert.equal(result.fits, false);
  assert.deepEqual({...result.suggestion}, {type: 'lsb', lsbBits: 2});
});

test('falls back to the latest start at the current LSB', () => {
  const limited = results.map(entry => ({...entry, max_start_unit: 18}));
  limited[0].max_start_unit = 19;
  limited[1].max_start_unit = 20;
  const result = evaluateLayout(21, 10, 2, limited);
  assert.equal(result.fits, false);
  assert.deepEqual({...result.suggestion}, {type: 'start', startUnit: 20});
});

test('reports no fitting start when every LSB maximum is null', () => {
  const noneFit = results.map(entry => ({
    ...entry,
    max_start_unit: null,
    max_payload_bytes_at_min_start: null,
  }));
  const result = evaluateLayout(21, 10, 1, noneFit);
  assert.equal(result.fits, false);
  assert.equal(result.fitsAnywhere, false);
  assert.equal(result.suggestion, null);
});
