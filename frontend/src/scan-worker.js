import { scanArchive } from './scanner';
import { scanDependencies } from './dependency-scan';

self.onmessage = async ({ data }) => {
  try {
    const sourceByPath = new Map();
    const packages = data.checkDependencies ? new Map() : undefined;
    const report = scanArchive(data.buffer, data.name, sourceByPath, packages);
    if (packages) await scanDependencies(report, packages);
    self.postMessage({ report, sourceByPath });
  } catch (error) {
    self.postMessage({ error: error.message || 'Invalid or unsupported ZIP archive.' });
  }
};
