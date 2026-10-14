import { scanArchive } from './scanner';
self.onmessage=({data})=>{try{self.postMessage({report:scanArchive(data.buffer,data.name)});}catch(e){self.postMessage({error:e.message||'Invalid or unsupported ZIP archive.'});}};
