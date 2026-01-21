"""FastAPI application for Phishing Detection System."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from config.settings import settings
from src.database.models import init_db, get_session
from src.ml.model import PhishingModel
from src.api.routes import detection, alerts, statistics


# Global instances
engine = None
model = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global engine, model

    # Startup
    print("Starting Phishing Detection System...")

    # Initialize database
    engine = init_db(settings.DATABASE_URL)
    print(f"Database initialized: {settings.DATABASE_URL}")

    # Load ML model
    if settings.MODEL_PATH.exists():
        model = PhishingModel(settings.MODEL_PATH)
        print(f"ML model loaded: {settings.MODEL_PATH}")
        print(f"Model version: {model.model_version}")
    else:
        print(f"WARNING: Model not found at {settings.MODEL_PATH}")
        print("Run 'python scripts/train_model.py' to train the model first.")
        model = None

    yield

    # Shutdown
    print("Shutting down...")


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="ML-powered phishing URL detection with PhishTank verification",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Mount static files
static_path = Path(__file__).resolve().parent.parent.parent / "web" / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Templates
templates_path = Path(__file__).resolve().parent.parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(templates_path))


def get_db():
    """Get database session."""
    session = get_session(engine)
    try:
        yield session
    finally:
        session.close()


def get_model():
    """Get ML model instance."""
    return model


# Include API routes
app.include_router(
    detection.router,
    prefix=settings.API_PREFIX,
    tags=["Detection"]
)
app.include_router(
    alerts.router,
    prefix=settings.API_PREFIX,
    tags=["Alerts"]
)
app.include_router(
    statistics.router,
    prefix=settings.API_PREFIX,
    tags=["Statistics"]
)


# Web UI routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "title": "Dashboard"}
    )


@app.get("/checker", response_class=HTMLResponse)
async def checker(request: Request):
    """URL checker page."""
    return templates.TemplateResponse(
        "checker.html",
        {"request": request, "title": "URL Checker"}
    )


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alerts page."""
    return templates.TemplateResponse(
        "alerts.html",
        {"request": request, "title": "Alerts"}
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_version": model.model_version if model else None
    }
