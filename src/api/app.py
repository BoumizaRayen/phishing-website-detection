"""
src/api/app.py
==============
FastAPI application factory.

Endpoints
---------
GET  /                        → serves the frontend (index.html)
GET  /api/v1/health           → model health-check
POST /api/v1/analyze          → full phishing analysis of a URL

Static files
------------
/static  → frontend/static/   (CSS, JS)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from src.api.services import analyze_url
from src.config import CORS_ORIGINS
from src.models.predict import get_predictor

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phishing_api")

# ── Paths ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent   # project root
FRONTEND_DIR = BASE_DIR / "frontend"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"

# ── FastAPI app ───────────────────────────────────────────────────────────
app = FastAPI(
    title="Phishing Website Detection API",
    description=(
        "ML-based real-time phishing detection. "
        "Submit a URL and receive a verdict, confidence score, risk level "
        "and top contributing features."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ── CORS ──────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files & templates ──────────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ── Middleware: request timing ────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0 = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    logger.info(
        "%s %s → %d  (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

from src.api.db import get_stats

@app.get(
    "/api/v1/stats",
    tags=["System"],
    summary="Get global ML monitoring stats",
)
async def fetch_stats():
    return get_stats()


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check",
)
async def health_check() -> HealthResponse:
    """Returns API status and confirms the model is loaded."""
    try:
        predictor = get_predictor()
        predictor._load()   # ensure loaded
        return HealthResponse(
            status="ok",
            model_loaded=True,
            n_features=predictor.n_features,
            model_trained_at=predictor.metadata.get("trained_at", ""),
        )
    except FileNotFoundError as exc:
        return HealthResponse(
            status="model_not_found",
            model_loaded=False,
            n_features=0,
            model_trained_at="",
        )
    except Exception as exc:
        logger.exception("Health check error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@app.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    tags=["Analysis"],
    summary="Analyse a URL for phishing",
    status_code=status.HTTP_200_OK,
)
async def analyze(request_body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyse a URL and return:
    - **verdict**: `phishing` or `legitimate`
    - **confidence**: probability (0–1)
    - **risk_level**: `low | medium | high | critical`
    - **top_features**: the most influential signals
    - **fetch_info**: HTTP fetch metadata
    """
    url = request_body.url
    logger.info("Received analysis request for: %s", url)

    try:
        response = await analyze_url(url)
        return response

    except FileNotFoundError as exc:
        # Model artefacts not yet exported
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Model not ready: {exc}. Run `python export_model.py` first.",
        )
    except AssertionError as exc:
        # Feature alignment error — critical bug
        logger.exception("Feature alignment error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal feature alignment error: {exc}",
        )
    except Exception as exc:
        logger.exception("Unexpected error analysing %s: %s", url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {exc}",
        )


# ── Global exception handler ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
    )
