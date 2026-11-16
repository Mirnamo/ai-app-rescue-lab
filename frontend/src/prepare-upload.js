import { unzipSync, zipSync } from 'fflate';

const MAX_UPLOAD_BYTES = 15 * 1024 * 1024;

export function prepareServerArchive(buffer) {
  const source = new Uint8Array(buffer);
  if (source.length > MAX_UPLOAD_BYTES) throw new Error('ZIP exceeds the 15 MB limit.');

  let entryCount = 0;
  let expandedBytes = 0;
  const files = unzipSync(source, {
    filter(entry) {
      if (++entryCount > 2000) throw new Error('Archive exceeds 2,000 entries.');

      const path = entry.name.replaceAll('\\', '/');
      if (path.includes('\0') || path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.split('/').includes('..')) {
        throw new Error('Unsafe archive path.');
      }

      expandedBytes += entry.originalSize;
      if (expandedBytes > 40 * 1024 * 1024 || entry.originalSize > 2 * 1024 * 1024) {
        throw new Error('Archive exceeds expanded size limits (40 MB total, 2 MB per file).');
      }

      const name = path.split('/').at(-1).toLowerCase();
      return name && name !== '.env' && !name.startsWith('.env.') && !name.endsWith('.env');
    },
  });

  if (!Object.keys(files).length) throw new Error('No files remain eligible for upload.');
  const upload = zipSync(files);
  if (upload.length > MAX_UPLOAD_BYTES) throw new Error('Prepared ZIP exceeds the 15 MB upload limit.');
  return { upload, files };
}
