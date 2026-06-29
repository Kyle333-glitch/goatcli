import { test } from 'node:test';
import assert from 'node:assert';
import {
  getShell,
  checkDirectoryWritable,
  checkPathLengthProblems,
} from './system.js';

test('getShell returns standard shell path or executable', () => {
  const shell = getShell();
  assert.strictEqual(typeof shell, 'string');
  assert.ok(shell.length > 0);
});

test('checkDirectoryWritable reports correctly for current working dir', () => {
  const cwd = process.cwd();
  const status = checkDirectoryWritable(cwd);
  assert.strictEqual(status.path, cwd);
  assert.strictEqual(status.exists, true);
  assert.strictEqual(status.writable, true);
});

test('checkPathLengthProblems identifies long paths', () => {
  const normalPath = 'C:\\short\\path';
  const longPath = 'C:\\' + 'a'.repeat(300);
  
  const results = checkPathLengthProblems([
    { name: 'Normal', path: normalPath },
    { name: 'Long', path: longPath },
  ]);

  const normalResult = results.find(r => r.name === 'Normal');
  const longResult = results.find(r => r.name === 'Long');

  assert.ok(normalResult);
  assert.ok(longResult);
  assert.strictEqual(normalResult.hasProblem, false);
  if (process.platform === 'win32') {
    assert.strictEqual(longResult.hasProblem, true);
  } else {
    assert.strictEqual(longResult.hasProblem, false);
  }
});
