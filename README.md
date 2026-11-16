# AI App Rescue Lab

[Open the app](https://enchanting-babka-ebc245.netlify.app/) · [Project wiki](https://github.com/Mirnamo/ai-app-rescue-lab/wiki)

## Scan a source ZIP

The React app accepts source ZIP archives and offers two analysis modes:

- **Python API:** The browser builds a new ZIP without files named `.env`, `.env.*`, or `*.env` anywhere in the archive, regardless of capitalization, and sends that copy to the configured FastAPI service for analysis.
- **Browser analysis:** Runs the static scanner in a Web Worker. The ZIP stays on the visitor's device.

The Python API also rejects ZIPs containing environment files before opening archive entries, including uploads sent directly to the API.

Both modes report heuristic signals with file locations and remediation guidance. Findings require human review; this is not a security certification or complete vulnerability scanner. The app does not execute or automatically repair uploaded code.

Both modes also flag disabled TLS certificate checks, possible secrets in log calls, unsafe deserialization, direct request input used as an outbound URL, and recognizable webhook routes without a recognizable signature verification call. These source checks cover common Python and JavaScript patterns. For webhook findings, check route middleware and shared helpers.

Rules flag possible hardcoded credentials (without displaying their values), dynamic execution, unsafe HTML rendering, debug mode, wildcard CORS, silent error handling, shell execution, client-controlled authorization signals, potentially unsafe SQL construction, large files, and missing test-file signals. Limits: 15 MB compressed, 40 MB expanded, 2 MB per entry, and 2,000 entries. Generated/dependency folders and binary files are skipped. Both modes reject unsafe archive paths. The Python analyzer also rejects symbolic links.

### Optional dependency advisories

Before choosing the ZIP, enable **Check dependencies for known vulnerabilities**. This option is off by default. Include a modern npm `package-lock.json` with a `packages` section or a `requirements.txt` with exact `==` version pins. The check covers versions listed in these files. It does not resolve unpinned dependencies.

The browser in Browser analysis mode, or the backend in Python API mode, sends package names, versions, and ecosystems to OSV.dev. The lookup checks up to 500 unique package versions. Matching advisories appear as medium-priority findings with links to OSV. The report shows how many versions were checked and indicates when results are partial, no supported versions were found, or OSV was unavailable. Source findings remain available in each case.

For direct API calls, pass the optional multipart field `check_dependencies=true` alongside the ZIP.

```bash
curl -F "file=@project.zip" -F "check_dependencies=true" http://localhost:8000/api/analyze
```

## Deploy the frontend and connect the Python API

Import this repository into Netlify and deploy `main`. The root `netlify.toml` configures the frontend base directory, build command, and publish directory.

Host the Python API separately using `backend/Dockerfile` (Docker build context: `backend`; HTTP port: `8000`; health check: `/health`). Configure these environment variables:

- On the backend host, set `ALLOWED_ORIGINS` to the exact Netlify site origin, without a trailing slash. You can provide comma-separated origins for production and preview domains.
- In Netlify, set `VITE_API_URL` to the backend's HTTPS origin, without a trailing slash, then trigger a new deploy.

When `VITE_API_URL` is present at build time, the UI defaults to Python API mode. Visitors can switch to browser analysis. Without it, the Python option is disabled and browser analysis remains available. The upload route is `POST /api/analyze`; health check is `GET /health`.

## Local verification

```bash
cd frontend
npm ci
npm test
npm run build
npm run dev
```

The API tests run with `cd backend && pytest`.
