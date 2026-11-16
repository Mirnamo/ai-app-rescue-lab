import { scanArchive } from './scanner';
self.onmessage = ({ data }) => {
  try {
    const sourceByPath = new Map();
    const report = scanArchive(data.buffer, data.name, sourceByPath);
    self.postMessage({ report, sourceByPath });
  } catch (error) {
    self.postMessage({ error: error.message || 'Invalid or unsupported ZIP archive.' });
  }
};
