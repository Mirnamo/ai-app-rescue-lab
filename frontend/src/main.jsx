import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

function App(){
  const [study,setStudy]=useState(null);const [selected,setSelected]=useState(null);const [tab,setTab]=useState("findings");const [error,setError]=useState("");
  useEffect(()=>{fetch(`${API}/api/case-study`).then(r=>{if(!r.ok)throw Error("Could not load case study");return r.json()}).then(setStudy).catch(e=>setError(e.message))},[]);
  if(error)return <main><div className="error">{error}. Confirm the API is running on port 8000.</div></main>;
  if(!study)return <main><div className="loading">Loading rescue evidence…</div></main>;
  return <main><nav><div className="brand"><span>AR</span><b>App Rescue Lab</b></div><div className="navright"><span className="live">CASE STUDY</span><a href="https://github.com/Mirnamo">GitHub ↗</a></div></nav>
  <header><div><p>RECOVERY REPORT / {study.application.toUpperCase()}</p><h1>From generated<br/>to <em>production-minded.</em></h1><div className="summary">{study.summary}</div></div><div className="scoreCard"><div><span>BEFORE</span><strong>{study.before_score}</strong></div><i>→</i><div className="after"><span>AFTER</span><strong>{study.after_score}</strong></div></div></header>
  <section className="stats"><article><strong>{study.metrics.findings_fixed}</strong><span>Findings fixed</span></article><article><strong>{study.metrics.tests_added}</strong><span>Test scenarios</span></article><article><strong>{study.metrics.protected_routes}</strong><span>Protected routes</span></article><article><strong>{study.metrics.audit_coverage}%</strong><span>Mutation audit coverage</span></article></section>
  <section className="phases">{study.phases.map((p,i)=><article key={p.name}><span>0{i+1}</span><div><b>{p.name}</b><small>{p.result}</small></div></article>)}</section>
  <div className="tabs"><button className={tab==="findings"?"active":""} onClick={()=>setTab("findings")}>Remediation findings</button><button className={tab==="architecture"?"active":""} onClick={()=>setTab("architecture")}>Architecture rescue</button></div>
  {tab==="findings"?<section className="workspace"><div className="panel list"><div className="head"><p>FIXED FINDINGS</p><h2>Evidence and remediation</h2></div>{study.findings.map(f=><button key={f.id} className={selected?.id===f.id?"selected":""} onClick={()=>setSelected(f)}><span className={`severity ${f.severity}`}>{f.severity}</span><div><b>{f.title}</b><small>{f.id} · {f.category}</small></div><i>→</i></button>)}</div><aside className="panel detail">{selected?<><p>{selected.id}</p><h2>{selected.title}</h2><label>Evidence</label><div className="evidence">{selected.evidence}</div><label>Implemented fix</label><div className="fix">{selected.remediation}</div><span className="resolved">✓ Resolved and verified</span></>:<div className="empty">Select a finding to see what was broken, why it mattered, and how it was repaired.</div>}</aside></section>:<Architecture/>}
  </main>
}
function Architecture(){return <section className="architecture"><div className="arch before"><p>BEFORE</p><h2>Generated monolith</h2><div className="node">React UI + role checks</div><div className="arrow">↓</div><div className="node risk">Unvalidated API + business logic</div><div className="arrow">↓</div><div className="node risk">Direct database access</div><small>Client trust · coupled logic · silent errors</small></div><div className="divider">→</div><div className="arch after"><p>AFTER</p><h2>Explicit trust boundaries</h2><div className="node">React interface</div><div className="arrow">↓</div><div className="node safe">Identity + policy + validation</div><div className="arrow">↓</div><div className="nodes"><span>Service</span><span>Repository</span><span>Audit</span></div><small>Server enforcement · typed contracts · traceable changes</small></div></section>}
createRoot(document.getElementById("root")).render(<App/>);

