import { unzipSync } from 'fflate';
const SKIP = /(^|\/)(node_modules|\.git|dist|build|vendor|\.venv)(\/|$)/;
const RULES = [
 ['SECRET','Possible hardcoded credential','high',/(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][^'"\n]{8,}['"]/i,'Move credentials to server-side environment variables; rotate any exposed real credentials.'],
 ['EVAL','Dynamic code execution','high',/\b(?:eval|exec)\s*\(/,'Avoid executing dynamic input; use explicit parsing and allowlisted operations.'],
 ['HTML','Unsafe HTML rendering signal','medium',/dangerouslySetInnerHTML|\.innerHTML\s*=/,'Check the source of HTML and sanitize untrusted content before rendering.'],
 ['DEBUG','Debug mode enabled','medium',/debug\s*[:=]\s*(?:true|True)\b/,'Disable debug mode in production configuration.'],
 ['CORS','Wildcard CORS policy','medium',/allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]/,'Review allowed origins and credential handling for sensitive endpoints.'],
 ['SILENT','Silent error handling signal','medium',/catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*pass\b|\.catch\s*\(\s*\(\)\s*=>\s*\[\s*\]/,'Return actionable errors and log failures without exposing secrets.'],
 ['SHELL','Shell execution enabled','high',/shell\s*=\s*True/,'Avoid shell execution for untrusted input; pass explicit argument lists.']
];
export function scanArchive(buffer, project) {
 const bytes=new Uint8Array(buffer);
 if(bytes.length>15*1024*1024) throw Error('ZIP exceeds the 15 MB limit.');
 let count=0,total=0;
 const files=unzipSync(bytes,{filter:f=>{
  if(++count>2000) throw Error('Archive exceeds 2,000 entries.');
  const path=f.name.replaceAll('\\','/');
  if(path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.split('/').includes('..')) throw Error('Unsafe archive path.');
  total+=f.originalSize;
  if(total>40*1024*1024 || f.originalSize>2*1024*1024) throw Error('Archive exceeds expanded size limits (40 MB total, 2 MB per file).');
  return !SKIP.test(path)&&!path.endsWith('/')&&/\.(js|jsx|ts|tsx|py|php|java|rb|go|json|ya?ml|toml|env|sql|html|css|md|txt)$|(^|\/)Dockerfile$|(^|\/)\.env$/.test(path);
 }});
 const findings=[],inventory=[];
 for(const [path,data] of Object.entries(files)) {
  if(data.includes(0)) continue;
  const source=new TextDecoder().decode(data),lines=source.split('\n');
  inventory.push({path,lines:lines.length});
  for(const [rule,title,severity,pattern,remediation] of RULES) {
   const match=pattern.exec(source); if(!match) continue;
   findings.push({id:`${rule}-${findings.length+1}`,title,severity,path,line:source.slice(0,match.index).split('\n').length,remediation,status:'Needs review'});
  }
  if(lines.length>500) findings.push({id:`SIZE-${findings.length+1}`,title:'Large file maintenance signal',severity:'low',path,line:1,remediation:'Review responsibilities and split cohesive modules where appropriate.',status:'Needs review'});
 }
 if(!inventory.length) throw Error('No supported text source files found in this ZIP.');
 if(!inventory.some(f=>/(test|spec)/i.test(f.path))) findings.push({id:'TEST-REVIEW',title:'No test files identified',severity:'medium',path:'Project',line:null,remediation:'Confirm tests exist outside the archive or add tests for authentication, validation, and error paths.',status:'Needs review'});
 findings.sort((a,b)=>['high','medium','low'].indexOf(a.severity)-['high','medium','low'].indexOf(b.severity));
 return {project,files:inventory,findings,summary:{files:inventory.length,lines:inventory.reduce((n,f)=>n+f.lines,0),high:findings.filter(f=>f.severity==='high').length},limitations:'Static heuristic review only. Signals may be false positives and absence of findings does not establish security. Code is not executed or automatically repaired. Review authentication, business logic, dependencies, and runtime behavior separately.'};
}
