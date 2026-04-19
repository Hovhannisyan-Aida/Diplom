from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.db.session import get_db
from app.schemas.user import UserCreate, UserInDB, Token
from app.crud import user as crud_user
from app.core.security import create_access_token, decode_access_token
from app.core.config import settings
from app.core.email import send_verification_email

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")
limiter = Limiter(key_func=get_remote_address)

token_blacklist: set = set()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token in token_blacklist:
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
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = crud_user.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    new_user = crud_user.create_user(db=db, user=user)
    send_verification_email(new_user.email, new_user.verification_token)
    return new_user

@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud_user.authenticate_user(db, email=form_data.username, password=form_data.password)
    if not user:
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

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    token_blacklist.add(token)
    return {"message": "Successfully logged out"}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = crud_user.get_user_by_verification_token(db, token)
    if not user:
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verify_error=invalid")
    if user.verification_token_expires < datetime.utcnow():
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verify_error=expired")
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.commit()
    return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?verified=true")

@router.get("/me", response_model=UserInDB)
def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user
