from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .config import settings
from .api.api import api_router
from .db.session import engine, Base
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title="Cyber Threat Intelligence Dashboard",
    description="A comprehensive platform for managing cyber threat intelligence",
    version="1.0.0",
    openapi_url=f"{settings.api_base_path}/openapi.json",
    docs_url=f"{settings.api_base_path}/docs",
    redoc_url=f"{settings.api_base_path}/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.api_base_path)

@app.get("/")
async def root():
    return {"message": "Cyber Threat Intelligence Dashboard API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(BASE_DIR / "static" / "favicon.ico")