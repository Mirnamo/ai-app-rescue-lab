# AI App Rescue Lab

## Visitor app — Netlify

The React app accepts source ZIP archives and offers two analysis modes:

- **Python API:** Sends the ZIP to the configured FastAPI service. The service scans it in memory and does not persist the archive.
- **Browser analysis:** Runs the limited static scanner in the visitor's browser; the ZIP stays on their device.

Both modes report heuristic signals with file locations and remediation guidance. Findings require human review; this is not a security certification or complete vulnerability scanner. The app does not execute or automatically repair uploaded code.

Rules flag possible hardcoded credentials (without displaying their values), dynamic execution, unsafe HTML rendering, debug mode, wildcard CORS, silent error handling, shell execution, large files, and missing test-file signals. Limits: 15 MB compressed, 40 MB expanded, 2 MB per supported file, and 2,000 entries. Generated/dependency folders and binary files are skipped. Unsafe archive paths and symlinks are rejected.

### Deploy the frontend and connect the Python API

Import this repository into Netlify and deploy `main`. The root `netlify.toml` configures the frontend base directory, build command, and publish directory.

Host the Python API separately using `backend/Dockerfile` (Docker build context: `backend`; HTTP port: `8000`; health check: `/health`). Configure these environment variables:

- On the backend host, set `ALLOWED_ORIGINS` to the exact Netlify site origin, without a trailing slash. You can provide comma-separated origins for production and preview domains.
- In Netlify, set `VITE_API_URL` to the backend's HTTPS origin, without a trailing slash, then trigger a new deploy.

When `VITE_API_URL` is present at build time, the UI defaults to Python API mode. Visitors can switch to browser analysis. Without it, the Python option is disabled and browser analysis remains available. The upload route is `POST /api/analyze`; health check is `GET /health`.

### Local verification

```bash
cd frontend
npm ci
npm test
npm run build
npm run dev
```

The API tests run with `cd backend && pytest`.

## Original remediation case study

The existing FastAPI service also provides the ticket and case-study endpoints used to demonstrate authorization, validation, error contracts, audit history, and testing. Demonstration identity headers are not production authentication.
