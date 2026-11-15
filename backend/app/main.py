from __future__ import annotations

import os
from uuid import uuid4
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .zip_analyzer import analyze_zip

app = FastAPI(title="AI App Rescue Lab", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if origin.strip()], allow_methods=["GET", "POST"], allow_headers=["*"])


@app.middleware("http")
async def correlation_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))[:80]
    try:
        response = await call_next(request)
    except Exception:
        return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "Unexpected server error", "request_id": request_id}})
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "AI App Rescue Lab API",
        "health": "/health",
        "analyze": "/api/analyze",
        "docs": "/docs",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze_project(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=415, detail="Upload a ZIP archive")
    try:
        data = await file.read(15 * 1024 * 1024 + 1)
        if len(data) > 15 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="ZIP exceeds the 15 MB limit.")
        filename = file.filename.rsplit("/", 1)[-1].rsplit(chr(92), 1)[-1]
        project = filename[:-4] if filename.lower().endswith(".zip") else filename
        return analyze_zip(data, project)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await file.close()
