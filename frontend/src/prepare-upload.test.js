import assert from 'node:assert/strict';
import test from 'node:test';
import { strFromU8, strToU8, unzipSync, zipSync } from 'fflate';
import { prepareServerArchive } from './prepare-upload.js';
import { scanArchive } from './scanner.js';

test('rebuilds the server upload without environment files at any depth', () => {
  const original = zipSync({
    '.env': strToU8('password="sample-secret"'),
    'config/.ENV.local': strToU8('secret'),
    'vendor\\prod.env': strToU8('secret'),
    'src/app.py': strToU8('print("hello")'),
    'env.md': strToU8('configuration notes'),
  });

  const { upload: archive, files } = prepareServerArchive(original.buffer);
  const upload = unzipSync(archive);
  assert.deepEqual(Object.keys(upload).sort(), ['env.md', 'src/app.py']);
  assert.deepEqual(Object.keys(files).sort(), Object.keys(upload).sort());
  assert.equal(strFromU8(upload['src/app.py']), 'print("hello")');
  assert.ok(scanArchive(original.buffer, 'local').findings.some(({ path, id }) => path === '.env' && id.startsWith('SECRET')));
});

test('blocks uploads with no remaining files or with unsafe paths', () => {
  const environmentOnly = zipSync({ '.env': strToU8('secret') });
  assert.throws(() => prepareServerArchive(environmentOnly.buffer), /No files remain/);
  const unsafe = zipSync({ '../app.py': strToU8('print("hello")') });
  assert.throws(() => prepareServerArchive(unsafe.buffer), /Unsafe archive path/);
});
