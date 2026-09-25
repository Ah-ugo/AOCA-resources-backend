from typing import Optional
from beanie import Document, Indexed
from pydantic import EmailStr, Field
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    STUDENT = "student"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"

class User(Document):
    email: Indexed(EmailStr, unique=True)
    hashed_password: str
    first_name: str
    last_name: str
    role: UserRole = UserRole.STUDENT
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    profile_image: Optional[str] = None
    bio: Optional[str] = None
    
    class Settings:
        name = "users"
