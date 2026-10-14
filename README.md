# AI App Rescue Lab

## Visitor app — Netlify

The public React app accepts source ZIP archives and performs static heuristic analysis in a browser worker. No backend or AI provider is required. Source code is not uploaded, executed, or automatically repaired. Visitors receive file/line locations, remediation guidance, file inventories, and downloadable JSON reports.

Rules flag possible hardcoded credentials (without displaying their values), dynamic execution, unsafe HTML rendering, debug mode, wildcard CORS, silent error handling, shell execution, large files, and missing test-file signals. Findings require human review; this is not a security certification or complete vulnerability scanner.

Limits: 15 MB compressed, 40 MB expanded, 2 MB per entry, 2,000 entries, 30-second analysis timeout. Generated/dependency folders and binary files are skipped. Unsafe archive paths are rejected. Archives are read in memory and never extracted to disk.

### Deploy

Import this repository into Netlify and deploy `main`. The root `netlify.toml` configures the frontend base directory, build command, and publish directory. No API URL or secret environment variables are needed.

### Local verification

```bash
cd frontend
npm ci
npm test
npm run build
npm run dev
```

## Original remediation case study

The Python FastAPI backend and supporting case-study files remain a separate demonstration of authorization, validation, error contracts, audit history, and testing. They are not exposed by the Netlify visitor app. Demonstration identity headers are not production authentication.
