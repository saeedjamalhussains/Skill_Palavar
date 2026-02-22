from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from app.auth.routes import router as auth_router
from app.banking.routes import router as banking_router
from app.banking.admin_routes import router as admin_router
from app.db.session import init_db
from app.core.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, specify the frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database
@app.on_event("startup")
def on_startup():
    init_db()
    if settings.PUBLIC_BASE_URL:
        print(f"🌐 Public URL (ngrok): {settings.PUBLIC_BASE_URL}")

# Include Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(banking_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)

# Serve index.html at root
@app.get("/")
def read_root():
    return FileResponse(os.path.join("frontend", "index.html"))

# Mount the entire frontend directory for static assets (styles, scripts, images)
app.mount("/", StaticFiles(directory="frontend"), name="frontend")

@app.get("/health")
def health_check():
    return {"status": "healthy"}