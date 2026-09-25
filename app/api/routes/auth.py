from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

from .common import (
    Token, User, UserCreate, UserResponse,
    authenticate_user, create_access_token, get_current_user,
    get_current_active_user, get_password_hash, get_user,
    parse_json, ACCESS_TOKEN_EXPIRE_MINUTES, db,
)
from datetime import datetime

router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login endpoint to get access token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=User)
async def register_user(user: UserCreate):
    """Register a new user."""
    try:
        if get_user(user.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        hashed_password = get_password_hash(user.password)
        user_data = user.dict()
        user_data.pop("password")
        user_data["hashed_password"] = hashed_password
        user_data["created_at"] = datetime.utcnow()
        user_data["updated_at"] = datetime.utcnow()
        user_data["disabled"] = False
        user_data["role"] = user_data.get("role", "student")

        result = db.users.insert_one(user_data)
        created_user = db.users.find_one({"_id": result.inserted_id})
        return parse_json(created_user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}",
        )


@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current authenticated user info."""
    return current_user
