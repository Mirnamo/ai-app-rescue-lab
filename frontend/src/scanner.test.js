import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync,strToU8} from 'fflate';
import {scanArchive} from './scanner.js';
const zip=files=>zipSync(Object.fromEntries(Object.entries(files).map(([p,s])=>[p,strToU8(s)]))).buffer;
test('reports source locations and guidance without exposing credentials',()=>{const report=scanArchive(zip({'app.js':'const api_key = "sensitive-value-123";\neval(input);','app.test.js':'test("valid",()=>{});'}),'demo');assert.equal(report.summary.files,2);assert.ok(report.findings.some(f=>f.id.startsWith('SECRET')&&f.line===1));assert.ok(report.findings.some(f=>f.id.startsWith('EVAL')&&f.line===2));assert.ok(!JSON.stringify(report).includes('sensitive-value-123'));assert.ok(!report.findings.some(f=>f.id==='TEST-REVIEW'));});
test('rejects traversal and malformed archives',()=>{assert.throws(()=>scanArchive(zip({'../app.js':'eval(input)'}),'bad'),/Unsafe/);assert.throws(()=>scanArchive(new Uint8Array([1,2,3]).buffer,'bad'));});
test('bounds expanded file size before decompression',()=>{assert.throws(()=>scanArchive(zip({'app.js':'a'.repeat(2*1024*1024+1)}),'large'),/expanded size/);});
test('skips dependencies and identifies missing tests as a signal',()=>{const report=scanArchive(zip({'app.js':'console.log("hello");','node_modules/library.js':'eval(input)'}),'demo');assert.equal(report.summary.files,1);assert.deepEqual(report.findings.map(f=>f.id),['TEST-REVIEW']);});

test('flags weak authorization and interpolated SQL with line evidence',()=>{const report=scanArchive(zip({'backend/routes.py':'def is_admin(headers):\n    return headers.get("X-User-Role") == "admin"\nquery = f"SELECT * FROM users WHERE email = \\'{email}\\'";','backend/routes.test.py':'assert True'}),'demo');const auth=report.findings.find(f=>f.id.startsWith('AUTH'));const sql=report.findings.find(f=>f.id.startsWith('SQL'));assert.equal(auth?.line,2);assert.equal(sql?.line,3);});
test('does not flag trusted principal roles or parameterized SQL',()=>{const report=scanArchive(zip({'backend/safe.py':'def is_admin(current_user):\n    return current_user.role == "admin"\ncursor.execute("SELECT * FROM users WHERE email = ?", (email,))','backend/safe.test.py':'assert True'}),'demo');assert.ok(!report.findings.some(f=>f.id.startsWith('AUTH')||f.id.startsWith('SQL')));});
