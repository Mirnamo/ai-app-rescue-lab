import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { prepareServerArchive } from "./prepare-upload";
import { FindingSource } from "./finding-source";
import { ReviewedFiles } from "./reviewed-files";
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

function DependencyScanStatus({ scan }) {
 if (!scan) return null;
 if (scan.status === 'unavailable') return <p>Dependency advisories could not be checked. Source findings are available below.</p>;
 if (scan.status === 'no-packages') return <p>No supported dependency versions found. Include a modern package-lock.json or pinned requirements.txt.</p>;
 if (scan.status === 'partial') return <p>Dependency check incomplete. Checked {scan.checked} package versions and received partial results.</p>;
 return <p>Checked {scan.checked} package versions for known vulnerabilities.</p>;
}

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
 const [mode,setMode]=useState(() => API && new URLSearchParams(window.location.search).get('analysis') !== 'browser' ? 'server' : 'browser');
 const [theme, setTheme] = useState(getInitialTheme);
 const [checkDependencies, setCheckDependencies] = useState(false);
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
 function changeMode(event) {
  const nextMode = event.target.value;
  const url = new URL(window.location.href);
  if (mode === 'server' && nextMode === 'browser') {
   url.searchParams.set('analysis', 'browser');
   window.location.replace(url);
   return;
  }
  url.searchParams.delete('analysis');
  window.history.replaceState(window.history.state, '', url);
  setMode(nextMode);
 }
 async function upload(event){
  const file=event.target.files?.[0];event.target.value="";if(!file)return;
  setError("");setReport(null);setSourceByPath(null);
  if(!file.name.toLowerCase().endsWith('.zip')){setError('Choose a ZIP archive.');return;}
  if(file.size>15*1024*1024){setError('ZIP exceeds the 15 MB limit.');return;}
  setBusy(true);
  if(mode==="server"){
   try{
    const { upload: archive, files } = prepareServerArchive(await file.arrayBuffer());
    const form = new FormData();
    form.append("file", new Blob([archive], {type: "application/zip"}), file.name);
    if (checkDependencies) form.append("check_dependencies", "true");
    const response=await fetch(`${API}/api/analyze`,{method:"POST",body:form,signal:AbortSignal.timeout(120000)});
    const body=await response.json();
    if(!response.ok)throw new Error(typeof body.detail==="string"?body.detail:"Analysis failed");
    const sources = new Map();
    const decoder = new TextDecoder('utf-8', { ignoreBOM: true });
    const filesByPath = new Map(Object.entries(files).map(([path, bytes]) => [path.replaceAll('\\', '/'), bytes]));
    for (const { path, endLine } of body.findings) {
     if (endLine && filesByPath.has(path) && !sources.has(path)) {
      sources.set(path, decoder.decode(filesByPath.get(path)).replace(/\r\n?/g, '\n'));
     }
    }
    setSourceByPath(sources);
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
   w.postMessage({buffer,name:file.name.replace(/\.zip$/i,''),checkDependencies},[buffer]);
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
 <header><div><h1>Find risks.<br/><em>Plan your rescue.</em></h1><div className="summary">Upload a source ZIP to identify common security and reliability signals with file locations and remediation guidance. {mode==="server"?"Your browser removes .env files from the ZIP before sending a copy to the Python API.":"Analysis runs locally in your browser; source code is not uploaded."}</div><label className="scanUpload">{busy?'Analyzing…':'Analyze your ZIP'}<input aria-label="Upload project ZIP" disabled={busy} type="file" accept=".zip" onChange={upload}/></label><p>15 MB ZIP · 40 MB expanded · 2,000 entries · 2 MB per file</p></div></header>
 <label>Analysis mode <select aria-label="Analysis mode" value={mode} disabled={busy} onChange={changeMode}><option value="server" disabled={!API}>Python API{!API?" (not configured)":""}</option><option value="browser">Browser analysis</option></select></label><p>{mode==="server"?"ZIP contents are processed temporarily by the configured Python API and are not stored.":"ZIP contents stay in your browser."} Maximum upload: 15 MB.</p>
 <label><input type="checkbox" checked={checkDependencies} disabled={busy} onChange={event => setCheckDependencies(event.target.checked)}/> Check dependencies for known vulnerabilities</label>
 <p>This sends package names and versions to OSV.dev.</p>
 {error&&<div className="error" role="alert">{error}</div>}{busy&&<div className="loading" role="status">{mode==="server"?"Preparing and analyzing ZIP…":"Reviewing source files…"}</div>}
 {report&&<><div className="reportHeader"><h2>{report.project}</h2><button type="button" onClick={downloadReport}>Download JSON report</button></div><dl className="reportSummary">
  <div><dt>Files reviewed</dt><dd>{report.summary.files}</dd></div>
  <div><dt>Lines reviewed</dt><dd>{report.summary.lines}</dd></div>
  <div><dt>Review signals</dt><dd>{report.findings.length}</dd></div>
  <div><dt>High priority</dt><dd>{report.summary.high}</dd></div>
 </dl>
 <p>{report.limitations}</p>
 <DependencyScanStatus scan={report.dependencyScan}/>
 <CorsOriginReview origins={report.corsOrigins} onAnswer={answerCorsOrigin}/>
 <ReviewedFiles files={report.files} findings={report.findings}/>
 <FindingsTable findings={report.findings} sourceByPath={sourceByPath}/></>}
 <p>This tool does not run your app, verify authentication, or certify production readiness. Review findings before changing code.</p></main>
}
function FindingsTable({ findings, sourceByPath }) {
 if (!findings.length) {
  return <p>No configured rule signals found. This does not establish that the app is secure.</p>;
 }

 return <div className="reportFindings" tabIndex={0} role="region" aria-label="Scan findings">
  <table className="findingsTable">
   <thead>
    <tr>
     <th scope="col">Severity</th>
     <th scope="col">Finding</th>
     <th scope="col">Location</th>
     <th scope="col">Suggested fix</th>
    </tr>
   </thead>
   <tbody>
    {findings.map(finding => <tr key={finding.id}>
     <td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td>
     <th scope="row">{finding.title}</th>
     <td>
      <div>{finding.path}{finding.endLine > finding.line ? ` · lines ${finding.line}–${finding.endLine}` : finding.line ? ` · line ${finding.line}` : ""}</div>
      {finding.endLine && sourceByPath?.has(finding.path) && (
       <FindingSource source={sourceByPath.get(finding.path)} path={finding.path} line={finding.line} endLine={finding.endLine}/>
      )}
     </td>
     <td>{finding.remediation}
      {finding.advisories?.length > 0 && <ul>{finding.advisories.map(id => (
       <li key={id}><a href={`https://osv.dev/vulnerability/${encodeURIComponent(id)}`}>{id}</a></li>
      ))}</ul>}
     </td>
    </tr>)}
   </tbody>
  </table>
 </div>;
}

function Architecture(){return <section className="architecture"><div className="arch before"><p>BEFORE</p><h2>Generated monolith</h2><div className="node">React UI + role checks</div><div className="arrow">↓</div><div className="node risk">Unvalidated API + business logic</div><div className="arrow">↓</div><div className="node risk">Direct database access</div><small>Client trust · coupled logic · silent errors</small></div><div className="divider">→</div><div className="arch after"><p>AFTER</p><h2>Explicit trust boundaries</h2><div className="node">React interface</div><div className="arrow">↓</div><div className="node safe">Identity + policy + validation</div><div className="arrow">↓</div><div className="nodes"><span>Service</span><span>Repository</span><span>Audit</span></div><small>Server enforcement · typed contracts · traceable changes</small></div></section>}
createRoot(document.getElementById("root")).render(<App/>);

