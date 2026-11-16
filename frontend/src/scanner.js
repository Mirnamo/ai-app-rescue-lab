import { unzipSync } from 'fflate';
import { collectDependencies } from './dependency-scan.js';
const SKIP = /(^|\/)(node_modules|\.git|dist|build|vendor|\.venv)(\/|$)/;
const CORS_SETTINGS = /\b(?:Access-Control-Allow-Origin['"]?\s*(?:\]\s*=|[:,])|(?:allow_origins|allowed_origins|allowedOrigins)['"]?\s*[:=])\s*(\[\s*(?:['"][^'"\r\n]*['"]\s*,\s*)*['"][^'"\r\n]*['"]\s*,?\s*\]|['"][^'"\r\n]*['"])/gi;
const CORS_ORIGIN = /['"](https?:\/\/(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?)['"]/gi;
const WEBHOOK_VERIFICATION = /\b(?:constructEvent(?:Async)?|construct_event|verify_signature|verifySignature|verify_webhook(?:_signature)?|verifyWebhook(?:Signature)?|timingSafeEqual|compare_digest)\s*\(/;
const ROUTE_DECLARATION = /\b(?:app|router|bp|blueprint)\.(?:get|post|put|patch|delete|route)\s*\(\s*['"]/i;
const RULES = [
 ['SECRET','Possible hardcoded credential','high',/(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][^'"\n]{8,}['"]/i,'Move credentials to server-side environment variables; rotate any exposed real credentials.'],
 ['EVAL','Dynamic code execution','high',/\b(?:eval|exec)\s*\(/,'Avoid executing dynamic input; use explicit parsing and allowlisted operations.'],
 ['HTML','Unsafe HTML rendering signal','medium',/dangerouslySetInnerHTML|\.innerHTML\s*=/,'Check the source of HTML and sanitize untrusted content before rendering.'],
 ['DEBUG','Debug mode enabled','medium',/debug\s*[:=]\s*(?:true|True)\b/,'Disable debug mode in production configuration.'],
 ['CORS','Wildcard CORS policy','medium',/allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]/i,'Review allowed origins and credential handling for sensitive endpoints.'],
 ['CORS-REFLECT','Possible CORS origin reflection','medium',/\bAccess-Control-Allow-Origin['"]\s*(?:\]\s*=|[:,])\s*(?:req|request)\s*\.\s*(?:headers\s*(?:\.\s*origin\b|\[\s*['"]origin['"]\s*\]|\.\s*get\s*\(\s*['"]origin['"]\s*\))|(?:get|header)\s*\(\s*['"]origin['"]\s*\))/i,'Check the request Origin against an explicit allowlist before returning it in Access-Control-Allow-Origin. Review credentialed access on sensitive endpoints.'],
 ['SILENT','Silent error handling signal','medium',/catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*pass\b|\.catch\s*\(\s*\(\)\s*=>\s*\[\s*\]/,'Return actionable errors and log failures without exposing secrets.'],
 ['AUTH','Client-controlled authorization signal','high',/(?:\b(?:request|req)\.headers|\bheaders)\s*(?:\.\s*get\s*\(\s*|\[\s*)['"]x-(?:user-)?(?:role|admin)['"]|\b(?:request|req)\.(?:json|body|form|query_params)(?:\(\))?(?:\.\s*get\s*\(\s*|\[\s*)['"](?:role|is_admin|isAdmin|admin)['"]/i,'Do not trust caller-supplied roles. Authenticate the user and enforce permissions server-side.'],
 ['SQL','Potentially unsafe SQL construction','high',/\b(?:select|insert|update|delete|replace)\b[^;\n]{0,500}(?:\{[A-Za-z_]\w*\}|\$\x7b[^}]+\}|\$[A-Za-z_]\w*|\+\s*(?:email|user_?input|input|request|req|params?|user_?id)\b|\.format\s*\()/i,'Use parameterized queries or prepared statements; never interpolate untrusted input into SQL.'],
 ['SHELL','Shell execution enabled','high',/shell\s*=\s*True/,'Avoid shell execution for untrusted input; pass explicit argument lists.'],
 ['TLS-VERIFY','TLS certificate verification disabled','high',/\b(?:(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|Client|AsyncClient)\s*\([^()]{0,500}\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b|ssl\._create_unverified_context\s*\()/,'Enable certificate verification and configure a trusted CA for private services.'],
 ['SECRET-LOG','Possible sensitive data written to logs','high',/\b(?:console\.(?:log|info|debug|warn|error)|(?:logger|logging|log)\.(?:debug|info|warning|warn|error|exception|critical))\s*\((?:"[^"\n]*"|'[^'\n]*'|[^'");\n]){0,300}?(?:\b(?:password|access[_-]?token|api[_-]?key|session[_-]?cookie)\b|\bheaders\s*(?:\.\s*authorization\b|\[\s*['"](?:authorization|cookie)['"]|\.\s*get\s*\(\s*['"](?:authorization|cookie)['"]))/,'Remove credentials and session data from log arguments or redact them before logging.'],
 ['DESERIALIZE','Potentially unsafe deserialization','high',/\b(?:(?:pickle|cPickle|dill|cloudpickle)\.loads?\s*\(|yaml\.unsafe_load\s*\(|yaml\.load\s*\([^)\n]{0,400}\bLoader\s*=\s*yaml\.(?:UnsafeLoader|Loader)\b|unserialize\s*\(\s*\$_(?:POST|GET|REQUEST)\b)/,'Use a data-only format and validate its schema when reading request or upload content.'],
 ['SSRF','Possible user-controlled outbound request','high',/\b(?:fetch|(?:requests|httpx|axios)\.(?:get|post|put|patch|delete|head)|(?:urllib\.request\.)?urlopen)\s*\(\s*(?:req|request)\s*\.\s*(?:query|query_params|body|form|params|json)(?:\s*\(\s*\))?\s*(?:\.\s*(?:url|target|destination|callbackUrl)\b|\[\s*['"](?:url|target|destination|callbackUrl)['"]\s*\]|\.\s*get\s*\(\s*['"](?:url|target|destination|callbackUrl)['"]\s*\))/,'Validate destinations against an explicit allowlist and enforce the policy after DNS resolution and redirects.'],
 ['WEBHOOK-SIGNATURE','Webhook signature verification needs review','medium',/\b(?:app|router|bp|blueprint)\.(?:post|route)\s*\(\s*['"][^'"\r\n]*webhooks?[^'"\r\n]*['"]/i,'Verify the provider signature over the raw request body before processing the event. Check route middleware and replay protection.'],
];
export function scanArchive(buffer, project, sourceByPath, packages) {
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
 const findings=[],inventory=[],corsOrigins=[];
 for(const [path,data] of Object.entries(files)) {
  if(data.includes(0)) continue;
  const source=new TextDecoder().decode(data).replace(/\r\n?/g, '\n'),lines=source.split('\n');
  inventory.push({path,lines:lines.length});
  if (packages) collectDependencies(source, path, packages);
  for (const setting of source.matchAll(CORS_SETTINGS)) {
   for (const match of setting[1].matchAll(CORS_ORIGIN)) {
    const offset = setting.index + setting[0].length - setting[1].length + match.index;
    corsOrigins.push({origin: match[1], path, line: source.slice(0, offset).split('\n').length});
   }
  }
  for(const [rule,title,severity,pattern,remediation] of RULES) {
   let match = pattern.exec(source);
   if (rule === 'WEBHOOK-SIGNATURE') {
    let offset = 0;
    while (match) {
     const start = offset + match.index + match[0].length;
     const handler = source.slice(start, start + 5000);
     const nextRoute = handler.search(ROUTE_DECLARATION);
     const end = nextRoute < 0 ? handler.length : nextRoute;
     if (!WEBHOOK_VERIFICATION.test(handler.slice(0, end))) {
      match.index += offset;
      break;
     }
     offset = start + end;
     match = pattern.exec(source.slice(offset));
    }
   }
   if (!match) continue;
   const line = source.slice(0, match.index).split('\n').length;
   const endLine = line + match[0].split('\n').length - 1;
   findings.push({id:`${rule}-${findings.length+1}`,title,severity,path,line,endLine,remediation,status:'Needs review'});
   sourceByPath?.set(path, source);
  }
  if(lines.length>500) findings.push({id:`SIZE-${findings.length+1}`,title:'Large file maintenance signal',severity:'low',path,line:1,remediation:'Review responsibilities and split cohesive modules where appropriate.',status:'Needs review'});
 }
 if(!inventory.length) throw Error('No supported text source files found in this ZIP.');
 if(!inventory.some(f=>/(test|spec)/i.test(f.path))) findings.push({id:'TEST-REVIEW',title:'No test files identified',severity:'medium',path:'Project',line:null,remediation:'Confirm tests exist outside the archive or add tests for authentication, validation, and error paths.',status:'Needs review'});
 findings.sort((a,b)=>['high','medium','low'].indexOf(a.severity)-['high','medium','low'].indexOf(b.severity));
 return {project,files:inventory,findings,corsOrigins,summary:{files:inventory.length,lines:inventory.reduce((n,f)=>n+f.lines,0),high:findings.filter(f=>f.severity==='high').length},limitations:'Static review only. Code patterns may produce false positives. Dependency results cover known advisories for checked versions. Review authentication, business logic, and runtime behavior separately.'};
}
