from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from app.models.user import UserRole
from beanie import PydanticObjectId

class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    profile_image: Optional[str] = None
    bio: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.STUDENT # usually overrides logic in service

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_image: Optional[str] = None
    bio: Optional[str] = None

class UserUpdateAdmin(UserUpdate):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    id: PydanticObjectId
    role: UserRole
    is_active: bool
    created_at: datetime
    
    class Config:
        json_encoders = {PydanticObjectId: str}
