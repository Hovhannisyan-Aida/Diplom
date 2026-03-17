from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1 import auth, scans, users, test
from app.db.session import engine
from app.db.base import Base

# Database tables-ների ստեղծում
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Automated Web Vulnerability Scanner"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix=f"{settings.API_V1_PREFIX}/auth", tags=["Authentication"])
app.include_router(users.router, prefix=f"{settings.API_V1_PREFIX}/users", tags=["Users"])
app.include_router(scans.router, prefix=f"{settings.API_V1_PREFIX}/scans", tags=["Scans"])
app.include_router(test.router, prefix=f"{settings.API_V1_PREFIX}/test", tags=["Test"])

@app.get("/")
def root():
    return {
        "message": "Vulnerability Scanner API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}