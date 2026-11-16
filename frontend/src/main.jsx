import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { prepareServerArchive } from "./prepare-upload";
import { FindingSource } from "./finding-source";
import "./styles.css";

const API = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

const THEME_STORAGE_KEY = "rescue-lab-theme";

function getInitialTheme() {
 try {
  return window.localStorage.getItem(THEME_STORAGE_KEY) === "light" ? "light" : "dark";
 } catch {
  return "dark";
 }
}

const CORS_REVIEW_OPTIONS = [
 ["yes", "Yes", "Recorded as intended access."],
 ["no", "No", "Remove this website from the API’s CORS settings."],
 ["unsure", "I’m not sure", "Check with the project owner before keeping this access."],
];

function CorsOriginReview({ origins, onAnswer }) {
 if (!origins?.length) return null;
 return <section className="corsReview">
  <h3>Review allowed websites</h3>
  {origins.map(({ origin, path, line, answer }, index) => (
   <fieldset key={index}>
    <legend>Should <strong>{origin}</strong> be allowed to read this API’s responses?</legend>
    <p>{path} · line {line}</p>
    <div className="corsChoices">
     {CORS_REVIEW_OPTIONS.map(([value, label]) => (
      <label key={value}>
       <input type="radio" name={`cors-origin-${index}`} checked={answer === value}
        onChange={() => onAnswer(index, value)} /> {label}
      </label>
     ))}
    </div>
    <p aria-live="polite">{CORS_REVIEW_OPTIONS.find(([value]) => value === answer)?.[2]}</p>
   </fieldset>
  ))}
 </section>;
}

function App(){
 const [report,setReport]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState("");
 const [mode,setMode]=useState(API?"server":"browser");
 const [theme, setTheme] = useState(getInitialTheme);
 const [sourceByPath, setSourceByPath] = useState(null);
 const worker=React.useRef(null);
 useEffect(()=>()=>worker.current?.terminate(),[]);
 React.useLayoutEffect(() => {
  document.documentElement.dataset.theme = theme;
  try {
   window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
   // The theme still works when browser storage is unavailable.
  }
 }, [theme]);
 async function upload(event){
  const file=event.target.files?.[0];event.target.value="";if(!file)return;
  setError("");setReport(null);setSourceByPath(null);
  if(!file.name.toLowerCase().endsWith('.zip')){setError('Choose a ZIP archive.');return;}
  if(file.size>15*1024*1024){setError('ZIP exceeds the 15 MB limit.');return;}
  setBusy(true);
  if(mode==="server"){
   try{
    const archive = prepareServerArchive(await file.arrayBuffer());
    const form = new FormData();
    form.append("file", new Blob([archive], {type: "application/zip"}), file.name);
    const response=await fetch(`${API}/api/analyze`,{method:"POST",body:form,signal:AbortSignal.timeout(120000)});
    const body=await response.json();
    if(!response.ok)throw new Error(typeof body.detail==="string"?body.detail:"Analysis failed");
    setReport(body);
   }catch(e){setError(`Python API analysis failed: ${e.message}. You can switch to Browser analysis and select the ZIP again.`);}
   finally{setBusy(false);}
   return;
  }
  try{
   const buffer=await file.arrayBuffer();worker.current?.terminate();
   const w=new Worker(new URL('./scan-worker.js',import.meta.url),{type:'module'});worker.current=w;
   const timeout=setTimeout(()=>{w.terminate();setBusy(false);setError('Analysis timed out. Try a smaller archive.');},30000);
   w.onmessage = ({ data }) => {
    clearTimeout(timeout);
    setBusy(false);
    if (data.error) setError(data.error);
    else {
     setSourceByPath(data.sourceByPath);
     setReport(data.report);
    }
    w.terminate();
   };
   w.onerror=()=>{clearTimeout(timeout);setBusy(false);setError('Analysis failed. Try a smaller source archive.');w.terminate();};
   w.postMessage({buffer,name:file.name.replace(/\.zip$/i,'')},[buffer]);
  }catch(e){setBusy(false);setError(e.message);}
 }
 function answerCorsOrigin(index, answer) {
  setReport(current => ({
   ...current,
   corsOrigins: current.corsOrigins.map((entry, position) => position === index ? { ...entry, answer } : entry),
  }));
 }
 function downloadReport() {
  const projectName = report.project.replace(/[^a-z0-9_-]+/gi, "-").slice(0, 80).replace(/^-+|-+$/g, "");
  const filename = projectName ? `${projectName}-security-report.json` : "app-rescue-report.json";
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
 }
 return <main><nav><div className="brand"><span>AR</span><b>AI App Rescue Lab</b></div>
 <div className="navright">
  <label className="themeControl">Theme <select value={theme} onChange={event => setTheme(event.target.value)}>
   <option value="light">Light</option>
   <option value="dark">Dark</option>
  </select></label>
  <a href="https://github.com/Mirnamo/ai-app-rescue-lab">GitHub ↗</a>
 </div></nav>
 <header><div><p>YOUR PROJECT / STATIC CODE REVIEW</p><h1>Find risks.<br/><em>Plan your rescue.</em></h1><div className="summary">Upload a source ZIP to identify common security and reliability signals with file locations and remediation guidance. {mode==="server"?"Your browser removes .env files from the ZIP before sending a copy to the Python API.":"Analysis runs locally in your browser; source code is not uploaded."}</div><label className="scanUpload">{busy?'Analyzing…':'Analyze your ZIP'}<input aria-label="Upload project ZIP" disabled={busy} type="file" accept=".zip" onChange={upload}/></label><p>15 MB ZIP · 40 MB expanded · 2,000 entries · 2 MB per file</p></div></header>
 <label>Analysis mode <select aria-label="Analysis mode" value={mode} disabled={busy} onChange={e=>setMode(e.target.value)}><option value="server" disabled={!API}>Python API{!API?" (not configured)":""}</option><option value="browser">Browser analysis</option></select></label><p>{mode==="server"?"ZIP contents are processed temporarily by the configured Python API and are not stored.":"ZIP contents stay in your browser."} Maximum upload: 15 MB.</p>\n {error&&<div className="error" role="alert">{error}</div>}{busy&&<div className="loading" role="status">{mode==="server"?"Preparing and analyzing ZIP…":"Reviewing source files…"}</div>}
 {report&&<><div className="reportHeader"><h2>{report.project}</h2><button type="button" onClick={downloadReport}>Download JSON report</button></div><section className="stats"><article><strong>{report.summary.files}</strong><span>Files reviewed</span></article><article><strong>{report.summary.lines}</strong><span>Lines reviewed</span></article><article><strong>{report.findings.length}</strong><span>Review signals</span></article><article><strong>{report.summary.high}</strong><span>High priority</span></article></section><p>{report.limitations}</p><CorsOriginReview origins={report.corsOrigins} onAnswer={answerCorsOrigin}/><section className="reportFindings">{report.findings.length?report.findings.map(f=><article className="panel" key={f.id}><span className={`severity ${f.severity}`}>{f.severity}</span><h3>{f.title}</h3><p>{f.path}{f.endLine > f.line ? ` · lines ${f.line}–${f.endLine}` : f.line ? ` · line ${f.line}` : ""}</p>
 {f.endLine && sourceByPath?.has(f.path) && <FindingSource source={sourceByPath.get(f.path)} path={f.path} line={f.line} endLine={f.endLine}/>}
 <p>{f.remediation}</p><small>Needs human review · No automatic fix applied</small></article>):<div className="panel">No configured rule signals found. This does not establish that the app is secure.</div>}</section><details><summary>Reviewed files</summary>{report.files.map(f=><p key={f.path}>{f.path} · {f.lines} lines</p>)}</details></>}
 <p>This tool does not run your app, verify authentication, or certify production readiness. Review findings before changing code.</p></main>
}
function Architecture(){return <section className="architecture"><div className="arch before"><p>BEFORE</p><h2>Generated monolith</h2><div className="node">React UI + role checks</div><div className="arrow">↓</div><div className="node risk">Unvalidated API + business logic</div><div className="arrow">↓</div><div className="node risk">Direct database access</div><small>Client trust · coupled logic · silent errors</small></div><div className="divider">→</div><div className="arch after"><p>AFTER</p><h2>Explicit trust boundaries</h2><div className="node">React interface</div><div className="arrow">↓</div><div className="node safe">Identity + policy + validation</div><div className="arrow">↓</div><div className="nodes"><span>Service</span><span>Repository</span><span>Audit</span></div><small>Server enforcement · typed contracts · traceable changes</small></div></section>}
createRoot(document.getElementById("root")).render(<App/>);

