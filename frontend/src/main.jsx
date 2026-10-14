import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";



function App(){
 const [report,setReport]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState("");
 const worker=React.useRef(null);
 useEffect(()=>()=>worker.current?.terminate(),[]);
 async function upload(event){
  const file=event.target.files?.[0];event.target.value="";if(!file)return;
  setError("");setReport(null);
  if(!file.name.toLowerCase().endsWith('.zip')){setError('Choose a ZIP archive.');return;}
  if(file.size>15*1024*1024){setError('ZIP exceeds the 15 MB limit.');return;}
  setBusy(true);
  try{
   const buffer=await file.arrayBuffer();worker.current?.terminate();
   const w=new Worker(new URL('./scan-worker.js',import.meta.url),{type:'module'});worker.current=w;
   const timeout=setTimeout(()=>{w.terminate();setBusy(false);setError('Analysis timed out. Try a smaller archive.');},30000);
   w.onmessage=({data})=>{clearTimeout(timeout);setBusy(false);if(data.error)setError(data.error);else setReport(data.report);w.terminate();};
   w.onerror=()=>{clearTimeout(timeout);setBusy(false);setError('Analysis failed. Try a smaller source archive.');w.terminate();};
   w.postMessage({buffer,name:file.name.replace(/\.zip$/i,'')},[buffer]);
  }catch(e){setBusy(false);setError(e.message);}
 }
 function download(){const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='app-rescue-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 return <main><nav><div className="brand"><span>AR</span><b>AI App Rescue Lab</b></div><a href="https://github.com/Mirnamo/ai-app-rescue-lab">GitHub ↗</a></nav>
 <header><div><p>YOUR PROJECT / STATIC CODE REVIEW</p><h1>Find risks.<br/><em>Plan your rescue.</em></h1><div className="summary">Upload a source ZIP to identify common security and reliability signals with file locations and remediation guidance. Analysis runs locally in your browser; source code is not uploaded.</div><label className="scanUpload">{busy?'Analyzing…':'Analyze your ZIP'}<input aria-label="Upload project ZIP" disabled={busy} type="file" accept=".zip" onChange={upload}/></label><p>15 MB ZIP · 40 MB expanded · 2,000 entries · 2 MB per file</p></div></header>
 {error&&<div className="error" role="alert">{error}</div>}{busy&&<div className="loading" role="status">Reviewing source files…</div>}
 {report&&<><h2>{report.project}</h2><section className="stats"><article><strong>{report.summary.files}</strong><span>Files reviewed</span></article><article><strong>{report.summary.lines}</strong><span>Lines reviewed</span></article><article><strong>{report.findings.length}</strong><span>Review signals</span></article><article><strong>{report.summary.high}</strong><span>High priority</span></article></section><button onClick={download}>Download JSON report</button><p>{report.limitations}</p><section className="reportFindings">{report.findings.length?report.findings.map(f=><article className="panel" key={f.id}><span className={`severity ${f.severity}`}>{f.severity}</span><h3>{f.title}</h3><p>{f.path}{f.line?` · line ${f.line}`:''}</p><p>{f.remediation}</p><small>Needs human review · No automatic fix applied</small></article>):<div className="panel">No configured rule signals found. This does not establish that the app is secure.</div>}</section><details><summary>Reviewed files</summary>{report.files.map(f=><p key={f.path}>{f.path} · {f.lines} lines</p>)}</details></>}
 <p>This tool does not run your app, verify authentication, or certify production readiness. Review findings before changing code.</p></main>
}
function Architecture(){return <section className="architecture"><div className="arch before"><p>BEFORE</p><h2>Generated monolith</h2><div className="node">React UI + role checks</div><div className="arrow">↓</div><div className="node risk">Unvalidated API + business logic</div><div className="arrow">↓</div><div className="node risk">Direct database access</div><small>Client trust · coupled logic · silent errors</small></div><div className="divider">→</div><div className="arch after"><p>AFTER</p><h2>Explicit trust boundaries</h2><div className="node">React interface</div><div className="arrow">↓</div><div className="node safe">Identity + policy + validation</div><div className="arrow">↓</div><div className="nodes"><span>Service</span><span>Repository</span><span>Audit</span></div><small>Server enforcement · typed contracts · traceable changes</small></div></section>}
createRoot(document.getElementById("root")).render(<App/>);

