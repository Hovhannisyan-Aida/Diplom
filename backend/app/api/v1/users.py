from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.schemas.user import UserInDB
from app.crud import user as crud_user
from fastapi.security import OAuth2PasswordBearer
from app.api.v1.auth import get_current_user, token_blacklist
from app.core.config import settings

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")

router = APIRouter()

@router.get("/{user_id}", response_model=UserInDB)
def read_user(user_id: int, db: Session = Depends(get_db),
              current_user: UserInDB = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    db_user = crud_user.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_own_account(
    token: str = Depends(_oauth2_scheme),
    db: Session = Depends(get_db),
    current_user: UserInDB = Depends(get_current_user),
):
    crud_user.delete_user(db, user_id=current_user.id)
    token_blacklist.add(token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
