"""
Shared models, helpers, and dependency functions used across all routers.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from bson import ObjectId
import cloudinary
import cloudinary.uploader
import os
import warnings
import json
from dotenv import load_dotenv

warnings.filterwarnings("ignore", message=".*trapped.*")
warnings.filterwarnings("ignore", category=UserWarning)
load_dotenv()

# ==================== ENVIRONMENT ====================
MONGO_URI = os.getenv("MONGO_URL") or os.getenv("MONGODB_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URL or MONGODB_URI environment variable is not set")

DB_NAME = os.getenv("MONGODB_DB_NAME") or "aoca_resources"

try:
    client = MongoClient(MONGO_URI)
    client.admin.command("ping")
    print("✅ MongoDB connection successful!")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    raise

db = client[DB_NAME]

cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET"),
)

try:
    cloudinary.api.ping()
    print("✅ Cloudinary connection successful!")
except Exception as e:
    print(f"⚠️ Cloudinary connection failed: {e}")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "3000"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== PYDANTIC MODELS ====================

PyObjectId = str  # Simplified for JSON serialisation


class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None
    bio: Optional[str] = None
    image: Optional[str] = None
    role: Optional[str] = "student"

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str}


class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class User(UserBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    disabled: Optional[bool] = False

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    bio: Optional[str] = None
    image: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None
    disabled: Optional[bool] = None


class UserResponse(User):
    courses: Optional[List[Dict[str, Any]]] = []


class ContactForm(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    service: str
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "john@example.com",
                "phone": "+2348012345678",
                "service": "General Inquiry",
                "message": "I'm interested in learning German",
            }
        }


class AdmissionInquiry(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    program: str
    location: str
    message: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "john@example.com",
                "phone": "+2348012345678",
                "program": "ielts",
                "location": "lagos",
                "message": "I'm interested in the IELTS preparation course",
            }
        }


class BlogPostBase(BaseModel):
    title: str
    slug: str
    excerpt: str
    content: str
    category: str
    tags: List[str]
    featured_image: Optional[str] = None
    is_published: bool = True


class BlogPostCreate(BlogPostBase):
    pass


class BlogPostUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    excerpt: Optional[str] = None
    content: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    featured_image: Optional[str] = None
    is_published: Optional[bool] = None


class BlogPost(BlogPostBase):
    id: Optional[str] = Field(None, alias="_id")
    author_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class BlogPostResponse(BlogPost):
    author: Optional[Dict[str, Any]] = None
    comments: Optional[List[Dict[str, Any]]] = []
    related_posts: Optional[List[Dict[str, Any]]] = []


class CommentBase(BaseModel):
    content: str
    name: Optional[str] = None
    email: Optional[EmailStr] = None


class CommentCreate(CommentBase):
    pass


class Comment(CommentBase):
    id: Optional[str] = Field(None, alias="_id")
    post_id: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    user_image: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class JobLocation(BaseModel):
    city: str
    state: Optional[str] = None
    country: str
    remote: bool = False
    hybrid: bool = False


class JobListingBase(BaseModel):
    title: str
    company: str
    description: str
    requirements: List[str]
    responsibilities: List[str]
    location: JobLocation
    salary_min: Optional[float] = None
    salary_max: Optional[float] = None
    salary_currency: Optional[str] = "USD"
    employment_type: str
    category: str
    experience_level: str
    education: Optional[str] = None
    skills: List[str]
    benefits: Optional[List[str]] = []
    application_url: Optional[str] = None
    application_email: Optional[EmailStr] = None
    application_deadline: Optional[datetime] = None
    is_featured: bool = False
    is_published: bool = True


class JobListingCreate(JobListingBase):
    pass


class JobListingUpdate(BaseModel):
    title: Optional[str] = None
    company: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[List[str]] = None
    responsibilities: Optional[List[str]] = None
    location: Optional[JobLocation] = None
    salary_min: Optional[float] = None
    salary_max: Optional[float] = None
    salary_currency: Optional[str] = None
    employment_type: Optional[str] = None
    category: Optional[str] = None
    experience_level: Optional[str] = None
    education: Optional[str] = None
    skills: Optional[List[str]] = None
    benefits: Optional[List[str]] = None
    application_url: Optional[str] = None
    application_email: Optional[EmailStr] = None
    application_deadline: Optional[datetime] = None
    is_featured: Optional[bool] = None
    is_published: Optional[bool] = None


class JobListing(JobListingBase):
    id: Optional[str] = Field(None, alias="_id")
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    views: int = 0
    applications_count: int = 0

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class JobListingResponse(JobListing):
    created_by_user: Optional[Dict[str, Any]] = None


class JobApplicationBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    job_id: Optional[str] = None
    cover_letter: Optional[str] = None
    resume_url: Optional[str] = None
    phone: str
    linkedin_url: Optional[str] = None
    portfolio_url: Optional[str] = None
    referral: Optional[str] = None
    additional_info: Optional[str] = None


class JobApplicationCreate(JobApplicationBase):
    pass


class JobApplicationUpdate(BaseModel):
    status: Optional[str] = None
    admin_notes: Optional[str] = None
    interview_date: Optional[datetime] = None


class JobApplication(JobApplicationBase):
    id: Optional[str] = Field(None, alias="_id")
    job_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    status: str = "applied"
    admin_notes: Optional[str] = None
    interview_date: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class JobApplicationResponse(JobApplication):
    job: Optional[Dict[str, Any]] = None


class JobCategoryBase(BaseModel):
    name: str
    description: Optional[str] = None
    icon: Optional[str] = None


class JobCategoryCreate(JobCategoryBase):
    pass


class JobCategoryUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None


class JobCategory(JobCategoryBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    job_count: int = 0

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class CourseBase(BaseModel):
    name: str
    description: str
    level: str
    duration: int
    image: Optional[str] = None
    instructor_id: Optional[str] = None
    syllabus: Optional[List[Dict[str, Any]]] = []


class CourseCreate(CourseBase):
    pass


class CourseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    level: Optional[str] = None
    duration: Optional[int] = None
    image: Optional[str] = None
    instructor_id: Optional[str] = None
    syllabus: Optional[List[Dict[str, Any]]] = None


class Course(CourseBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class CourseResponse(Course):
    instructor: Optional[Dict[str, Any]] = None
    students: Optional[List[Dict[str, Any]]] = []
    classes: Optional[List[Dict[str, Any]]] = []
    assignments: Optional[List[Dict[str, Any]]] = []
    progress: Optional[float] = 0


class ModuleBase(BaseModel):
    course_id: str
    title: str
    description: Optional[str] = None
    order: int


class ModuleCreate(ModuleBase):
    pass


class LessonBase(BaseModel):
    module_id: str
    title: str
    content_type: str  # live, recorded, materials
    url: Optional[str] = None
    materials: Optional[List[Dict[str, str]]] = []
    order: int


class LessonCreate(LessonBase):
    pass


class AssessmentBase(BaseModel):
    course_id: str
    title: str
    type: str  # quiz, test, assignment, final
    questions: Optional[List[Dict[str, Any]]] = []
    passing_score: Optional[int] = None
    due_date: Optional[datetime] = None


class AssessmentCreate(AssessmentBase):
    pass


class AssignmentBase(BaseModel):
    course_id: str
    title: str
    description: str
    due_date: datetime
    points: int
    resources: Optional[List[Dict[str, str]]] = []


class AssignmentCreate(AssignmentBase):
    pass


class AssignmentUpdate(BaseModel):
    course_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[datetime] = None
    points: Optional[int] = None
    resources: Optional[List[Dict[str, str]]] = None


class Assignment(AssignmentBase):
    id: Optional[str] = Field(None, alias="_id")
    course_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    submissions: Optional[List[Dict[str, Any]]] = []

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class AssignmentResponse(Assignment):
    course: Optional[Dict[str, Any]] = None
    submission_count: Optional[int] = 0


class ClassBase(BaseModel):
    course_id: str
    title: str
    description: str
    date: datetime
    duration: int
    meet_link: str
    instructor_id: Optional[str] = None
    recording_link: Optional[str] = None
    materials: Optional[List[Dict[str, str]]] = []


class ClassCreate(ClassBase):
    pass


class ClassUpdate(BaseModel):
    course_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    date: Optional[datetime] = None
    duration: Optional[int] = None
    meet_link: Optional[str] = None
    instructor_id: Optional[str] = None
    recording_link: Optional[str] = None
    materials: Optional[List[Dict[str, str]]] = None


class ClassResponse(ClassBase):
    id: Optional[str] = Field(None, alias="_id")
    course_id: str
    instructor_id: Optional[str] = None
    course: Optional[Dict[str, Any]] = None
    instructor: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


class ResourceBase(BaseModel):
    title: str
    description: str
    type: str
    url: str
    level: str
    category: str


class ResourceCreate(ResourceBase):
    pass


class ResourceUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    level: Optional[str] = None
    category: Optional[str] = None


class ResourceResponse(ResourceBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str, datetime: lambda dt: dt.isoformat()}
        populate_by_name = True


# ==================== HELPERS ====================


def parse_json(data):
    """Convert MongoDB documents to JSON-serialisable format."""
    if data is None:
        return None
    if isinstance(data, ObjectId):
        return str(data)
    if isinstance(data, datetime):
        return data.isoformat()
    if isinstance(data, list):
        return [parse_json(item) for item in data]
    if isinstance(data, dict):
        return {key: parse_json(value) for key, value in data.items()}
    return data


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(f"Password verification warning: {e}")
        return False


def get_password_hash(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(f"Password hashing warning: {e}")
        raise HTTPException(
            status_code=500,
            detail="Password hashing service temporarily unavailable",
        )


def get_user(email: str) -> Optional[UserInDB]:
    user = db.users.find_one({"email": email})
    if user:
        user["_id"] = str(user["_id"])
        return UserInDB(**user)
    return None


def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==================== AUTH DEPENDENCIES ====================


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required.",
        )
    return current_user


async def get_instructor_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    if current_user.role not in ["instructor", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Instructor access required.",
        )
    return current_user
