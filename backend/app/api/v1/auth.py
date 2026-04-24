import os
import logging
import threading
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status

logger = logging.getLogger(__name__)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import redis as redis_lib
from app.db.session import get_db
from app.schemas.user import UserCreate, UserInDB, Token
from app.crud import user as crud_user
from app.core.security import create_access_token, decode_access_token, create_refresh_token, decode_refresh_token
from app.core.config import settings
from app.core.email import send_verification_email

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")
limiter = Limiter(key_func=get_remote_address)

try:
    _redis = redis_lib.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
    _redis.ping()
except Exception:
    _redis = None

def _blacklist_token(token: str, expires_delta_seconds: int = None):
    if _redis is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token blacklist unavailable — Redis is not connected"
        )
    ttl = expires_delta_seconds or (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    _redis.setex(f"bl:{token}", ttl, "1")

def _is_blacklisted(token: str) -> bool:
    if _redis is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token validation unavailable — Redis is not connected"
        )
    try:
        return _redis.exists(f"bl:{token}") == 1
    except Exception:
        return False

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if _is_blacklisted(token):
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception

    user = crud_user.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception

    return user

@router.post("/register", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    db_user = crud_user.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    new_user = crud_user.create_user(db=db, user=user)
    logger.info(f"New user registered: {new_user.email}")
    thread = threading.Thread(
        target=send_verification_email,
        args=(new_user.email, new_user.verification_token),
        daemon=True,
    )
    thread.start()
    return new_user

@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud_user.authenticate_user(db, email=form_data.username, password=form_data.password)
    if not user:
        logger.warning(f"Failed login attempt for email: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in. Check your inbox for the verification link.",
        )

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/api/v1/auth/refresh",
    )
    logger.info(f"User logged in: {user.email}")
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh", response_model=Token)
@limiter.limit("10/minute")
def refresh(request: Request, response: Response, refresh_token: str = Cookie(default=None), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not refresh_token:
        raise credentials_exception
    payload = decode_refresh_token(refresh_token)
    if payload is None:
        raise credentials_exception
    email: str = payload.get("sub")
    if not email:
        raise credentials_exception
    user = crud_user.get_user_by_email(db, email=email)
    if not user or not user.is_verified:
        raise credentials_exception

    new_access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    new_refresh_token = create_refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/api/v1/auth/refresh",
    )
    logger.info(f"Token refreshed for user: {user.email}")
    return {"access_token": new_access_token, "token_type": "bearer"}

@router.post("/logout")
@limiter.limit("10/minute")
def logout(request: Request, response: Response, token: str = Depends(oauth2_scheme)):
    _blacklist_token(token)
    response.delete_cookie(key="refresh_token", path="/api/v1/auth/refresh")
    logger.info("User logged out")
    return {"message": "Successfully logged out"}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = crud_user.get_user_by_verification_token(db, token)
    if not user:
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verify_error=invalid")
    expires = user.verification_token_expires
    if not expires:
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verify_error=invalid")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verify_error=expired")
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.commit()
    return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verified=true")

class ResendVerificationRequest(BaseModel):
    email: str

@router.post("/resend-verification")
@limiter.limit("2/minute")
def resend_verification(request: Request, body: ResendVerificationRequest, db: Session = Depends(get_db)):
    user = crud_user.get_user_by_email(db, email=body.email)
    if not user or user.is_verified:
        return {"message": "If that email exists and is unverified, a new link has been sent."}
    new_token = crud_user.reset_verification_token(db, user)
    thread = threading.Thread(
        target=send_verification_email,
        args=(user.email, new_token),
        daemon=True,
    )
    thread.start()
    return {"message": "If that email exists and is unverified, a new link has been sent."}

@router.get("/me", response_model=UserInDB)
def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user
