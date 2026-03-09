from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.schemas.user import UserInDB
from app.crud import user as crud_user
from app.api.v1.auth import get_current_user

router = APIRouter()

@router.get("/{user_id}", response_model=UserInDB)
def read_user(user_id: int, db: Session = Depends(get_db),
              current_user: UserInDB = Depends(get_current_user)):
    """Օգտատիրոջ ստացում ID-ով"""
    db_user = crud_user.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Օգտատերը չի գտնվել")
    return db_user