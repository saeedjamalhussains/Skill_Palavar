from fastapi import FastAPI
from app.auth.routes import router as auth_router
from app.banking.routes import router as banking_router
from app.banking.admin_routes import router as admin_router
from app.db.session import init_db
from app.core.config import settings
from fastapi.middleware.cors import CORSMiddleware

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

# Include Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(banking_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    return {"message": "Welcome to ZTNA Secure Banking API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
