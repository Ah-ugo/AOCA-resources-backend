from fastapi import FastAPI, Depends, HTTPException, status, Query, UploadFile, File, WebSocket, WebSocketDisconnect

from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Dict, Any, Optional, Literal, Union
from pydantic import conint
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
import cloudinary
import cloudinary.uploader
from pymongo import MongoClient
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import json
import warnings
import uuid
import csv
from io import StringIO
import httpx

# Suppress passlib warnings
warnings.filterwarnings("ignore", message=".*trapped.*")
warnings.filterwarnings("ignore", category=UserWarning)

# Load environment variables
load_dotenv()

# ==================== DATABASE CONNECTION ====================
MONGO_URI = os.getenv("MONGO_URL")
if not MONGO_URI:
    raise ValueError("MONGO_URL environment variable is not set")

try:
    client = MongoClient(MONGO_URI)
    # Test connection
    client.admin.command('ping')
    print("✅ MongoDB connection successful!")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    raise

db = client["aoca_resources"]

# ==================== CLOUDINARY CONFIGURATION ====================
cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET")
)

try:
    cloudinary.api.ping()
    print("✅ Cloudinary connection successful!")
except Exception as e:
    print(f"⚠️ Cloudinary connection failed: {e}")
    print("File upload features may not work properly.")

# ==================== JWT CONFIGURATION ====================
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "3000"))

# ==================== PASSWORD HASHING ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== PYDANTIC MODELS ====================

def validate_objectid(value: str) -> str:
    if not ObjectId.is_valid(value):
        raise ValueError("Invalid ObjectId")
    return value

PyObjectId = str  # Simplified for JSON serialization

# User models
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


# Contact Form Model
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
                "message": "I'm interested in learning German"
            }
        }


# Admission Inquiry Model
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
                "message": "I'm interested in the IELTS preparation course"
            }
        }


# Blog models
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


# Comment models
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


# Job Board Models
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
    job_id: str
    cover_letter: Optional[str] = None
    resume_url: str
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


# Course models
class CourseBase(BaseModel):
    name: str
    description: str
    level: str
    duration: int
    price: float
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
    price: Optional[float] = None
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


# Assignment models
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


# Class models
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


# Resource models
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


# ==================== FASTAPI APP INITIALIZATION ====================
app = FastAPI(
    title="AOCA Resources API",
    description="Complete API for AOCA Resources Limited website",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ==================== CORS CONFIGURATION ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)


class ConnectionManager:
    def __init__(self):
        # Store active connections: {user_id: [WebSocket]}
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await connection.send_text(message)

    async def broadcast(self, message: str):
        for user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await connection.send_text(message)

manager = ConnectionManager()



# ==================== EXCEPTION HANDLERS ====================
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# ==================== HELPER FUNCTIONS ====================
def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(f"Password verification warning: {e}")
        return False


def get_password_hash(password):
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(f"Password hashing warning: {e}")
        raise HTTPException(
            status_code=500,
            detail="Password hashing service temporarily unavailable"
        )


def get_user(email: str):
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


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_admin_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user



async def get_instructor_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role not in ["instructor", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Instructor access required."
        )
    return current_user


def parse_json(data):
    """Convert MongoDB documents to JSON serializable format"""
    if data is None:
        return None
    if isinstance(data, list):
        return [parse_json(item) for item in data]
    if isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            if isinstance(value, ObjectId):
                new_data[key] = str(value)
            elif isinstance(value, datetime):
                new_data[key] = value.isoformat()
            elif isinstance(value, dict):
                new_data[key] = parse_json(value)
            elif isinstance(value, list):
                new_data[key] = [parse_json(item) for item in value]
            else:
                new_data[key] = value
        return new_data
    return data


# ==================== PUBLIC ENDPOINTS ====================

@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "Welcome to AOCA Resources API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check MongoDB connection
        client.admin.command('ping')
        mongodb_status = "connected"
    except:
        mongodb_status = "disconnected"

    return {
        "status": "healthy",
        "mongodb": mongodb_status,
        "timestamp": datetime.utcnow().isoformat()
    }


# ==================== CONTACT FORM ENDPOINTS ====================

@app.post("/contact", status_code=status.HTTP_201_CREATED)
async def submit_contact_form(contact: ContactForm):
    """
    Submit contact form from the contact page
    """
    try:
        contact_data = contact.dict()
        contact_data["created_at"] = datetime.utcnow()
        contact_data["is_read"] = False

        result = db.contact_submissions.insert_one(contact_data)

        return {
            "message": "Thank you for your message. We'll get back to you soon!",
            "id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit contact form: {str(e)}"
        )


# ==================== ADMISSION INQUIRY ENDPOINTS ====================

@app.post("/admission-inquiry", status_code=status.HTTP_201_CREATED)
async def submit_admission_inquiry(inquiry: AdmissionInquiry):
    """
    Submit admission inquiry from the popup form
    """
    try:
        inquiry_data = inquiry.dict()
        inquiry_data["created_at"] = datetime.utcnow()
        inquiry_data["is_read"] = False
        inquiry_data["status"] = "pending"

        result = db.admission_inquiries.insert_one(inquiry_data)

        return {
            "message": "Thank you for your interest! Our admissions team will contact you shortly.",
            "status": "success",
            "id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit inquiry: {str(e)}"
        )


# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login endpoint to get access token
    """
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


@app.post("/register", response_model=User)
async def register_user(user: UserCreate):
    """
    Register a new user
    """
    try:
        # Check if user already exists
        if get_user(user.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Create new user
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
            detail=f"Registration failed: {str(e)}"
        )




@app.get("/courses", response_model=Dict[str, Any])
async def get_public_courses(
    skip: int = Query(0, ge=0),
    limit: int = Query(12, ge=1, le=50),
    level: Optional[str] = None,
    search: Optional[str] = None,
):
    """Public course catalog — no authentication required."""
    query: dict = {}
    if level:
        query["level"] = level
    if search:
        query["$or"] = [
            {"name":  {"$regex": search, "$options": "i"}},
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
 
    courses = list(db.courses.find(query).skip(skip).limit(limit))
    total = db.courses.count_documents(query)
 
    for c in courses:
        if c.get("instructor_id"):
            inst = db.users.find_one({"_id": c["instructor_id"]})
            if inst:
                c["instructor"] = {
                    "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                    "email": inst.get("email"),
                }
        # Normalise: ensure both 'name' and 'title' present
        c.setdefault("title", c.get("name", ""))
        c.setdefault("name",  c.get("title", ""))
 
    return {"courses": parse_json(courses), "total": total, "skip": skip, "limit": limit}



@app.get("/courses/{course_id}", response_model=Dict[str, Any])
async def get_public_course(course_id: str):
    """Public single course — no authentication required."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
 
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
 
    if course.get("instructor_id"):
        inst = db.users.find_one({"_id": course["instructor_id"]})
        if inst:
            course["instructor"] = {
                "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email"),
            }
 
    # Normalise name/title
    course.setdefault("title", course.get("name", ""))
    course.setdefault("name",  course.get("title", ""))
 
    course["enrollment_count"] = db.user_courses.count_documents({
        "course_id": ObjectId(course_id), "status": "active"
    })
    return parse_json(course)


# ==================== BLOG ENDPOINTS ====================

@app.get("/blog/posts", response_model=Dict[str, Any])
async def get_blog_posts(
        skip: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=100),
        category: Optional[str] = None,
        search: Optional[str] = None
):
    """
    Get all blog posts with pagination and filtering
    """
    try:
        query = {"is_published": True}
        
        if category:
            query["category"] = category
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"excerpt": {"$regex": search, "$options": "i"}},
                {"content": {"$regex": search, "$options": "i"}}
            ]

        posts = list(db.blog_posts.find(query)
                     .sort("created_at", -1)
                     .skip(skip)
                     .limit(limit))

        total = db.blog_posts.count_documents(query)

        # Add author details
        for post in posts:
            if post.get("author_id"):
                author = db.users.find_one({"_id": ObjectId(post["author_id"])})
                if author:
                    post["author"] = {
                        "name": f"{author.get('first_name', '')} {author.get('last_name', '')}",
                        "role": author.get("role", ""),
                        "image": author.get("image", "")
                    }

        return {
            "posts": parse_json(posts),
            "total": total,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/blog/posts/{post_id}", response_model=Dict[str, Any])
async def get_blog_post(post_id: str):
    """
    Get a single blog post by ID
    """
    try:
        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        # Get author details
        if post.get("author_id"):
            author = db.users.find_one({"_id": post["author_id"]})
            if author:
                post["author"] = {
                    "name": f"{author.get('first_name', '')} {author.get('last_name', '')}",
                    "role": author.get("role", ""),
                    "image": author.get("image", "")
                }

        # Get comments
        comments = list(db.comments.find({"post_id": ObjectId(post_id)})
                       .sort("created_at", -1))
        post["comments"] = parse_json(comments)

        # Get related posts
        related_posts = list(db.blog_posts.find({
            "category": post["category"],
            "_id": {"$ne": ObjectId(post_id)},
            "is_published": True
        }).limit(3))
        post["related_posts"] = parse_json(related_posts)

        return parse_json(post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/blog/posts", response_model=BlogPostResponse)
async def create_blog_post(
        post: BlogPostCreate,
        current_user: User = Depends(get_current_active_user)
):
    """
    Create a new blog post (admin/editor only)
    """
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

        post_data = post.dict()
        post_data["author_id"] = ObjectId(current_user.id)
        post_data["created_at"] = datetime.utcnow()
        post_data["updated_at"] = datetime.utcnow()

        result = db.blog_posts.insert_one(post_data)
        created_post = db.blog_posts.find_one({"_id": result.inserted_id})

        return parse_json(created_post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/blog/posts/{post_id}", response_model=BlogPostResponse)
async def update_blog_post(
        post_id: str,
        post_update: BlogPostUpdate,
        current_user: User = Depends(get_current_active_user)
):
    """
    Update a blog post (admin/editor only)
    """
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        existing_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not existing_post:
            raise HTTPException(status_code=404, detail="Post not found")

        update_data = post_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()

        db.blog_posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": update_data}
        )

        updated_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        return parse_json(updated_post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/blog/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blog_post(
        post_id: str,
        current_user: User = Depends(get_current_active_user)
):
    """
    Delete a blog post (admin/editor only)
    """
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        existing_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not existing_post:
            raise HTTPException(status_code=404, detail="Post not found")

        db.blog_posts.delete_one({"_id": ObjectId(post_id)})
        db.comments.delete_many({"post_id": ObjectId(post_id)})

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/blog/posts/{post_id}/comments", response_model=Comment)
async def add_comment(
        post_id: str,
        comment: CommentCreate,
        current_user: Optional[User] = Depends(get_current_user)
):
    """
    Add a comment to a blog post
    """
    try:
        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        comment_data = comment.dict()
        comment_data["post_id"] = ObjectId(post_id)
        comment_data["created_at"] = datetime.utcnow()

        if current_user:
            comment_data["user_id"] = ObjectId(current_user.id)
            comment_data["user_name"] = f"{current_user.first_name} {current_user.last_name}"
            comment_data["user_image"] = current_user.image

        result = db.comments.insert_one(comment_data)
        created_comment = db.comments.find_one({"_id": result.inserted_id})

        return parse_json(created_comment)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== JOB BOARD PUBLIC ENDPOINTS ====================

@app.get("/careers/jobs", response_model=Dict[str, Any])
async def get_job_listings(
        skip: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=50),
        category: Optional[str] = None,
        location: Optional[str] = None,
        remote: Optional[bool] = None,
        employment_type: Optional[str] = None,
        experience_level: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: int = -1
):
    """
    Get all published job listings with filters
    """
    try:
        query = {"is_published": True}

        if category:
            query["category"] = category
        if location:
            query["location.city"] = {"$regex": location, "$options": "i"}
        if remote is not None:
            query["location.remote"] = remote
        if employment_type:
            query["employment_type"] = employment_type
        if experience_level:
            query["experience_level"] = experience_level
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"company": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
                {"skills": {"$in": [{"$regex": search, "$options": "i"}]}}
            ]

        jobs = list(db.job_listings.find(query)
                    .sort(sort_by, sort_order)
                    .skip(skip)
                    .limit(limit))

        total = db.job_listings.count_documents(query)

        # Increment view count
        for job in jobs:
            db.job_listings.update_one(
                {"_id": job["_id"]},
                {"$inc": {"views": 1}}
            )

        # Get filter options
        categories = list(db.job_categories.find())
        
        locations = list(db.job_listings.aggregate([
            {"$match": {"is_published": True}},
            {"$group": {"_id": "$location.city", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))

        employment_types = list(db.job_listings.aggregate([
            {"$match": {"is_published": True}},
            {"$group": {"_id": "$employment_type", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))

        experience_levels = list(db.job_listings.aggregate([
            {"$match": {"is_published": True}},
            {"$group": {"_id": "$experience_level", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))

        return {
            "jobs": parse_json(jobs),
            "total": total,
            "skip": skip,
            "limit": limit,
            "filters": {
                "categories": parse_json(categories),
                "locations": parse_json(locations),
                "employment_types": parse_json(employment_types),
                "experience_levels": parse_json(experience_levels)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/careers/jobs/{job_id}", response_model=Dict[str, Any])
async def get_job_listing(job_id: str):
    """
    Get a single job listing by ID
    """
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        job = db.job_listings.find_one({"_id": ObjectId(job_id), "is_published": True})
        if not job:
            raise HTTPException(status_code=404, detail="Job listing not found")

        # Increment view count
        db.job_listings.update_one(
            {"_id": ObjectId(job_id)},
            {"$inc": {"views": 1}}
        )

        # Get creator info
        if job.get("created_by"):
            creator = db.users.find_one({"_id": job["created_by"]})
            if creator:
                job["created_by_user"] = {
                    "id": str(creator["_id"]),
                    "name": f"{creator.get('first_name', '')} {creator.get('last_name', '')}",
                    "email": creator.get("email", "")
                }

        # Get similar jobs
        similar_jobs = list(db.job_listings.find({
            "category": job["category"],
            "_id": {"$ne": ObjectId(job_id)},
            "is_published": True
        }).sort("created_at", -1).limit(3))

        job["similar_jobs"] = parse_json(similar_jobs)

        return parse_json(job)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/careers/categories", response_model=List[Dict[str, Any]])
async def get_job_categories():
    """
    Get all job categories with job counts
    """
    try:
        categories = list(db.job_categories.find().sort("name", 1))
        
        for category in categories:
            job_count = db.job_listings.count_documents({
                "category": category["name"],
                "is_published": True
            })
            category["job_count"] = job_count

        return parse_json(categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/careers/jobs/{job_id}/apply", response_model=JobApplicationResponse)
async def apply_for_job(
        job_id: str,
        application: JobApplicationCreate
):
    """
    Apply for a job (public endpoint)
    """
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        job = db.job_listings.find_one({"_id": ObjectId(job_id), "is_published": True})
        if not job:
            raise HTTPException(status_code=404, detail="Job listing not found")

        # Check deadline
        if job.get("application_deadline"):
            if datetime.utcnow() > job["application_deadline"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Application deadline has passed"
                )

        # Check for duplicate
        existing = db.job_applications.find_one({
            "email": application.email,
            "job_id": ObjectId(job_id)
        })

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You have already applied for this job"
            )

        application_data = application.dict()
        application_data["job_id"] = ObjectId(job_id)
        application_data["created_at"] = datetime.utcnow()
        application_data["updated_at"] = datetime.utcnow()
        application_data["status"] = "applied"

        result = db.job_applications.insert_one(application_data)

        # Update job application count
        db.job_listings.update_one(
            {"_id": ObjectId(job_id)},
            {"$inc": {"applications_count": 1}}
        )

        created_application = db.job_applications.find_one({"_id": result.inserted_id})
        created_application["job"] = {
            "id": str(job["_id"]),
            "title": job["title"],
            "company": job["company"]
        }

        return parse_json(created_application)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/careers/upload/resume")
async def upload_resume(file: UploadFile = File(...)):
    """
    Upload a resume file (public endpoint)
    """
    try:
        # Check file type
        allowed_extensions = ['.pdf', '.doc', '.docx']
        file_ext = os.path.splitext(file.filename)[1].lower()

        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
            )

        # Read file content
        contents = await file.read()
        
        # Check file size (limit to 5MB)
        if len(contents) > 5 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 5MB"
            )
        
        # Generate unique ID
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        unique_id = str(uuid.uuid4())[:8]
        public_id = f"resume_{timestamp}_{unique_id}"
        
        # Upload to Cloudinary
        try:
            result = cloudinary.uploader.upload(
                contents,
                resource_type="raw",
                folder="resumes",
                public_id=public_id
            )
        except Exception as e:
            print(f"First upload attempt failed: {str(e)}")
            result = cloudinary.uploader.upload(
                contents,
                folder="resumes",
                public_id=public_id
            )

        return {"url": result["secure_url"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Upload error: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error uploading file: {str(e)}"
        )



@app.post("/students/apply", response_model=Dict[str, Any])
async def student_apply(
    body: dict,
    current_user: User = Depends(get_current_active_user)
):
    """
    Student expresses interest in a course.
    Creates a pending record. Admin must approve + assign.
    Body: { course_id: str, message?: str }
    """
    course_id = body.get("course_id")
    if not course_id or not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="course_id required")
 
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
 
    user_oid = ObjectId(current_user.id)
    course_oid = ObjectId(course_id)
 
    existing = db.user_courses.find_one({"user_id": user_oid, "course_id": course_oid})
    if existing:
        return {"message": "Application already exists", "status": existing.get("status")}
 
    doc = {
        "user_id": user_oid,
        "course_id": course_oid,
        "class_id": None,
        "status": "pending",
        "enrolled_at": None,
        "approved_at": None,
        "approved_by": None,
        "note": body.get("message", ""),
        "created_at": datetime.utcnow(),
    }
    result = db.user_courses.insert_one(doc)
    return {"message": "Application submitted. You will be notified when approved.", "id": str(result.inserted_id)}
 


# ==================== IMAGE UPLOAD ENDPOINT ====================

@app.post("/upload/image")
async def upload_image(
        file: UploadFile = File(...),
        current_user: User = Depends(get_current_active_user)
):
    """
    Upload an image (authenticated users only)
    """
    try:
        contents = await file.read()
        result = cloudinary.uploader.upload(contents)
        return {"url": result["secure_url"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== DASHBOARD ENDPOINTS ====================



@app.get("/dashboard", response_model=Dict[str, Any])
async def get_user_dashboard(
    current_user: User = Depends(get_current_active_user)
):
    """Master student dashboard — one call for everything."""
    user_oid = ObjectId(current_user.id)
 
    # FIX #2: only active enrollments
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids  = [e["course_id"] for e in enrollments]
    courses_raw = list(db.courses.find({"_id": {"$in": course_ids}}))
 
    courses = []
    for c in courses_raw:
        prog = db.progress.find_one({"user_id": user_oid, "course_id": c["_id"]})
        c.setdefault("title", c.get("name", ""))
        c.setdefault("name",  c.get("title", ""))
        courses.append({
            **parse_json(c),
            "progress":       prog.get("percentage", 0) if prog else 0,
            "last_lesson_id": str(prog["last_lesson_id"]) if prog and prog.get("last_lesson_id") else None,
        })
 
    upcoming_classes = list(
        db.classes.find({"course_id": {"$in": course_ids}, "date": {"$gte": datetime.utcnow()}})
        .sort("date", 1).limit(5)
    )
    for cls in upcoming_classes:
        if cls.get("instructor_id"):
            inst = db.users.find_one({"_id": cls["instructor_id"]})
            if inst:
                cls["instructor"] = {"name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip()}
 
    pending_assignments = list(
        db.assignments.find({"course_id": {"$in": course_ids}})
        .sort("due_date", 1).limit(10)
    )
 
    levels     = list({c.get("level") for c in courses_raw if c.get("level")})
    resources  = list(db.resources.find({"level": {"$in": levels}}).limit(6)) if levels else []
 
    return {
        "courses":             courses,
        "upcoming_classes":    parse_json(upcoming_classes),
        "pending_assignments": parse_json(pending_assignments),
        "resources":           parse_json(resources),
    }

@app.get("/dashboard/overview", response_model=Dict[str, Any])
async def get_dashboard_overview(current_user: User = Depends(get_current_active_user)):
    """
    Get dashboard overview for current user
    """
    try:
        # Get user's courses
        user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
        course_ids = [uc["course_id"] for uc in user_courses]

        # Get course details
        courses = list(db.courses.find({"_id": {"$in": course_ids}}))

        # Get upcoming classes
        upcoming_classes = list(db.classes.find({
            "course_id": {"$in": course_ids},
            "date": {"$gte": datetime.utcnow()}
        }).sort("date", 1).limit(3))

        # Get pending assignments
        pending_assignments = list(db.assignments.find({
            "course_id": {"$in": course_ids},
            "due_date": {"$gte": datetime.utcnow()},
            "submissions.user_id": {"$ne": ObjectId(current_user.id)}
        }).sort("due_date", 1).limit(5))

        # Calculate progress for each course
        for course in courses:
            progress = db.progress.find_one({
                "user_id": ObjectId(current_user.id),
                "course_id": course["_id"]
            })
            course["progress"] = progress["percentage"] if progress else 0

        return {
            "courses": parse_json(courses),
            "upcoming_classes": parse_json(upcoming_classes),
            "pending_assignments": parse_json(pending_assignments),
            "user": parse_json(current_user.dict())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/courses", response_model=List[Dict[str, Any]])
async def get_user_courses_dashboard(
    current_user: User = Depends(get_current_active_user)
):
    user_oid    = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids  = [e["course_id"] for e in enrollments]
    courses     = list(db.courses.find({"_id": {"$in": course_ids}}))
 
    result = []
    for c in courses:
        prog = db.progress.find_one({"user_id": user_oid, "course_id": c["_id"]})
        c.setdefault("title", c.get("name", ""))
        c.setdefault("name",  c.get("title", ""))
        c["progress"] = prog.get("percentage", 0) if prog else 0
        result.append(parse_json(c))
    return result


@app.get("/dashboard/courses/{course_id}", response_model=Dict[str, Any])
async def get_course_for_student_v2(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Student course detail — used by VideoPlayer.jsx."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
 
    enrollment = db.user_courses.find_one({
        "user_id":   ObjectId(str(current_user.id)),
        "course_id": ObjectId(course_id),
        "status":    "active",
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")
 
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
 
    course.setdefault("title", course.get("name", ""))
    course.setdefault("name",  course.get("title", ""))
 
    if course.get("instructor_id"):
        inst = db.users.find_one({"_id": course["instructor_id"]})
        if inst:
            course["instructor"] = {
                "name":  f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email"),
            }
 
    # BUG 8 FIX: safe module fetch — no __contains__ hack
    modules_from_collection = list(
        db.modules.find({"course_id": ObjectId(course_id)}).sort("order", 1)
    )
    course["modules"] = modules_from_collection or course.get("modules", [])
 
    return parse_json(course)

@app.get("/dashboard/assignments", response_model=Dict[str, Any])
async def get_user_assignments_dashboard(
    current_user: User = Depends(get_current_active_user),
    status: Optional[str] = None,
):
    user_oid    = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids  = [e["course_id"] for e in enrollments]
 
    query: dict = {"course_id": {"$in": course_ids}}
    now = datetime.utcnow()
 
    if status == "pending":
        query["due_date"] = {"$gte": now}
        # exclude assignments where this user has submitted
        query["submissions.user_id"] = {"$ne": user_oid}
    elif status == "completed":
        query["submissions.user_id"] = user_oid
    elif status == "overdue":
        query["due_date"] = {"$lt": now}
        query["submissions.user_id"] = {"$ne": user_oid}
 
    assignments = list(db.assignments.find(query).sort("due_date", 1))
 
    for a in assignments:
        course = db.courses.find_one({"_id": a.get("course_id")})
        if course:
            a["course"] = {"id": str(course["_id"]), "name": course.get("name")}
 
        # Compute per-assignment status
        submitted = any(str(s.get("user_id")) == str(user_oid) for s in a.get("submissions", []))
        if submitted:
            a["status"] = "completed"
        elif a.get("due_date") and a["due_date"] < now:
            a["status"] = "overdue"
        else:
            a["status"] = "pending"
 
    return {"assignments": parse_json(assignments)}
 


@app.get("/dashboard/classes", response_model=Dict[str, Any])
async def get_user_classes_dashboard(
    current_user: User = Depends(get_current_active_user),
    upcoming: bool = True,
):
    user_oid    = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids  = [e["course_id"] for e in enrollments]  # already ObjectIds from DB
 
    now = datetime.utcnow()
    date_filter = {"$gte": now} if upcoming else {"$lt": now}
    sort_dir    = 1 if upcoming else -1
 
    # FIX #12: course_id in classes collection is an ObjectId — match correctly
    classes = list(
        db.classes.find({"course_id": {"$in": course_ids}, "date": date_filter})
        .sort("date", sort_dir).limit(20)
    )
 
    for cls in classes:
        course = db.courses.find_one({"_id": cls.get("course_id")})
        if course:
            cls["course"] = {"id": str(course["_id"]), "name": course.get("name")}
        if cls.get("instructor_id"):
            inst = db.users.find_one({"_id": cls["instructor_id"]})
            if inst:
                cls["instructor"] = {
                    "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip()
                }
 
    return {"classes": parse_json(classes)}


@app.get("/dashboard/classes/{class_id}", response_model=Dict[str, Any])
async def get_class_for_student_dashboard(
    class_id: str,
    current_user: User = Depends(get_current_active_user),
):
    if not ObjectId.is_valid(class_id):
        raise HTTPException(status_code=400, detail="Invalid class ID")
 
    cls = db.classes.find_one({"_id": ObjectId(class_id)})
    if not cls:
        raise HTTPException(status_code=404, detail="Class not found")
 
    if cls.get("course_id"):
        course = db.courses.find_one({"_id": cls["course_id"]})
        if course:
            cls["course"] = {"_id": str(course["_id"]), "name": course.get("name")}
 
    if cls.get("instructor_id"):
        inst = db.users.find_one({"_id": cls["instructor_id"]})
        if inst:
            cls["instructor"] = {
                "_id":   str(inst["_id"]),
                "name":  f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email"),
            }
 
    return parse_json(cls)


@app.get("/dashboard/resources", response_model=Dict[str, Any])
async def get_learning_resources_dashboard(
    current_user: User = Depends(get_current_active_user),
    category: Optional[str] = None,
    search: Optional[str] = None,
):
    user_oid    = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids  = [e["course_id"] for e in enrollments]
    courses     = list(db.courses.find({"_id": {"$in": course_ids}}))
    levels      = list({c.get("level") for c in courses if c.get("level")})
 
    query: dict = {}
    if levels:
        query["level"] = {"$in": levels}
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"title":       {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
 
    resources = list(db.resources.find(query))
    return {"resources": parse_json(resources)}


@app.get("/dashboard/resources/categories", response_model=Dict[str, Any])
async def get_resource_categories_dashboard(
    current_user: User = Depends(get_current_active_user),
):
    cats = db.resources.distinct("category")
    return {"categories": [{"id": c, "name": c} for c in cats if c]}


@app.get("/dashboard/profile", response_model=Dict[str, Any])
async def get_dashboard_profile(
    current_user: User = Depends(get_current_active_user),
):
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": parse_json(user)}


@app.put("/dashboard/profile", response_model=Dict[str, Any])
async def update_dashboard_profile(
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    # FIX #6: whitelist only safe updatable fields — never email/role/password via this endpoint
    ALLOWED = {"first_name", "last_name", "phone", "address", "bio", "image"}
    update_data = {k: v for k, v in body.items() if k in ALLOWED and v is not None}
 
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")
 
    update_data["updated_at"] = datetime.utcnow()
    db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": update_data})
    updated = db.users.find_one({"_id": ObjectId(current_user.id)})
    return {"user": parse_json(updated)}



@app.get("/dashboard/progress/{course_id}", response_model=Dict[str, Any])
async def get_course_progress_fixed(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
 
    # FIX #10: require active status, not just any enrollment
    enrollment = db.user_courses.find_one({
        "user_id":   ObjectId(current_user.id),
        "course_id": ObjectId(course_id),
        "status":    "active",
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")
 
    progress = db.progress.find_one({
        "user_id":   ObjectId(current_user.id),
        "course_id": ObjectId(course_id),
    })
 
    completed_ids = [str(lid) for lid in (progress.get("completed_lesson_ids", []) if progress else [])]
 
    course      = db.courses.find_one({"_id": ObjectId(course_id)})
    all_lessons = []
    for mod in (course.get("modules", []) if course else []):
        all_lessons.extend(mod.get("lessons", []))
 
    total = len(all_lessons)
    done  = len(completed_ids)
    pct   = round((done / total) * 100) if total else 0
 
    return {
        "course_id":            course_id,
        "completed_lesson_ids": completed_ids,
        "total_lessons":        total,
        "completed_count":      done,
        "percentage":           pct,
        "last_lesson_id":       str(progress["last_lesson_id"]) if progress and progress.get("last_lesson_id") else None,
        "last_active":          progress["last_active"].isoformat() if progress and progress.get("last_active") else None,
    }


@app.post("/dashboard/progress/lesson/{lesson_id}/complete", response_model=Dict[str, Any])
async def mark_lesson_complete(
    lesson_id: str,
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    """
    Mark a lesson complete. Idempotent — safe to call twice.
    Auto-generates certificate when course reaches 100%.
    Body: { course_id: str }
    """
    course_id = body.get("course_id")
    if not course_id or not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="course_id required")
    if not ObjectId.is_valid(lesson_id):
        raise HTTPException(status_code=400, detail="Invalid lesson ID")
 
    lesson_oid = ObjectId(lesson_id)
    course_oid = ObjectId(course_id)
    user_oid   = ObjectId(str(current_user.id))
 
    # Require active enrollment
    enrollment = db.user_courses.find_one({
        "user_id": user_oid, "course_id": course_oid, "status": "active"
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")
 
    # Upsert progress — add lesson to completed set
    db.progress.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {
            "$addToSet": {"completed_lesson_ids": lesson_oid},
            "$set": {"last_lesson_id": lesson_oid, "last_active": datetime.utcnow()},
        },
        upsert=True,
    )
 
    # Recalculate percentage
    progress = db.progress.find_one({"user_id": user_oid, "course_id": course_oid})
    course    = db.courses.find_one({"_id": course_oid})
    all_lessons: list = []
    for mod in (course.get("modules", []) if course else []):
        all_lessons.extend(mod.get("lessons", []))
 
    total = len(all_lessons)
    done  = len(progress.get("completed_lesson_ids", []) if progress else [])
    pct   = round((done / total) * 100) if total else 0
 
    db.progress.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$set": {"percentage": pct}},
    )
 
    # Auto-generate certificate at 100%
    certificate_id = None
    if pct == 100:
        existing_cert = db.certificates.find_one({"user_id": user_oid, "course_id": course_oid})
        if not existing_cert:
            cert = {
                "user_id":           user_oid,
                "course_id":         course_oid,
                "user_name":         f"{current_user.first_name} {current_user.last_name}".strip(),
                "course_name":       course.get("name", "") if course else "",
                "issued_at":         datetime.utcnow(),
                "verification_code": str(uuid.uuid4())[:8].upper(),
            }
            res = db.certificates.insert_one(cert)
            certificate_id = str(res.inserted_id)
 
    return {
        "lesson_id":      lesson_id,
        "percentage":     pct,
        "completed":      True,
        "course_complete": pct == 100,
        "certificate_id": certificate_id,
    }



@app.get("/dashboard/courses/{course_id}/resume", response_model=Dict[str, Any])
async def get_resume_state(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Returns the lesson the student should resume. Used by the dashboard 'Continue' card."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
 
    progress = db.progress.find_one({
        "user_id":   ObjectId(str(current_user.id)),
        "course_id": ObjectId(course_id),
    })
    last_id = progress.get("last_lesson_id") if progress else None
 
    return {
        "course_id":      course_id,
        "last_lesson_id": str(last_id) if last_id else None,
        "percentage":     progress.get("percentage", 0) if progress else 0,
    }



@app.get("/dashboard/certificates", response_model=List[Dict[str, Any]])
async def get_my_certificates(
    current_user: User = Depends(get_current_active_user),
):
    """Student's earned certificates."""
    certs = list(
        db.certificates.find({"user_id": ObjectId(str(current_user.id))})
        .sort("issued_at", -1)
    )
    return parse_json(certs)
 
 
@app.get("/certificates/{verification_code}", response_model=Dict[str, Any])
async def verify_certificate(verification_code: str):
    """Public endpoint — verify a certificate by its QR/code."""
    cert = db.certificates.find_one({"verification_code": verification_code.upper()})
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found or invalid code")
    return parse_json(cert)


@app.get("/students/my-enrollments", response_model=List[Dict[str, Any]])
async def get_my_enrollments(
    current_user: User = Depends(get_current_active_user)
):
    """
    Student sees all their enrollment records — pending, approved, active, etc.
    They never see other students.
    """
    user_oid = ObjectId(current_user.id)
    records = list(db.user_courses.find({"user_id": user_oid}))
 
    result = []
    for rec in records:
        course = db.courses.find_one({"_id": rec.get("course_id")})
        class_ = db.classes.find_one({"_id": rec.get("class_id")}) if rec.get("class_id") else None
        result.append({
            **parse_json(rec),
            "course_name":  course.get("name") if course else None,
            "course_level": course.get("level") if course else None,
            "class_title":  class_.get("title") if class_ else None,
            "class_date":   class_.get("date").isoformat() if class_ and class_.get("date") else None,
            "meet_link":    class_.get("meet_link") if class_ else None,
        })
    return result



# ==================== INSTRUCTOR ENDPOINTS ====================

@app.websocket("/instructor/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
                # Persist the message to DB
                if payload.get("text") and payload.get("chatId"):
                    db.messages.insert_one({
                        "sender_id":    ObjectId(user_id),
                        "recipient_id": ObjectId(payload["chatId"]),
                        "text":         payload["text"],
                        "is_read":      False,
                        "created_at":   datetime.utcnow(),
                    })
                # Deliver to recipient if online
                await manager.send_personal_message(data, payload.get("chatId", user_id))
            except Exception:
                await manager.send_personal_message(data, user_id)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)


@app.get("/instructor/dashboard/stats", response_model=Dict[str, Any])
async def get_instructor_stats_v2(
    current_user: User = Depends(get_instructor_user),
):
    """Instructor dashboard statistics."""
    try:
        # BUG 9 FIX: always str() before ObjectId to avoid double-wrapping
        user_oid = ObjectId(str(current_user.id))
 
        total_courses = db.courses.count_documents({"instructor_id": user_oid})
        instructor_courses = list(db.courses.find({"instructor_id": user_oid}, {"_id": 1}))
        course_ids = [c["_id"] for c in instructor_courses]
 
        # Count only active enrollments
        total_students = db.user_courses.count_documents({
            "course_id": {"$in": course_ids}, "status": "active"
        })
        total_assignments = db.assignments.count_documents({"course_id": {"$in": course_ids}})
 
        pending_grading = 0
        for assignment in db.assignments.find({"course_id": {"$in": course_ids}}):
            for sub in assignment.get("submissions", []):
                if not sub.get("grade"):
                    pending_grading += 1
 
        recent_enrollments = list(db.user_courses.aggregate([
            {"$match": {"course_id": {"$in": course_ids}, "status": "active"}},
            {"$sort": {"enrolled_at": -1}},
            {"$limit": 5},
            {"$lookup": {"from": "users",   "localField": "user_id",   "foreignField": "_id", "as": "student"}},
            {"$lookup": {"from": "courses", "localField": "course_id", "foreignField": "_id", "as": "course"}},
            {"$unwind": {"path": "$student", "preserveNullAndEmptyArrays": True}},
            {"$unwind": {"path": "$course",  "preserveNullAndEmptyArrays": True}},
            {"$project": {
                "student_name": {"$concat": ["$student.first_name", " ", "$student.last_name"]},
                "course_name":  "$course.name",
                "enrolled_at":  1,
            }},
        ]))
 
        return {
            "stats": {
                "total_courses":    total_courses,
                "total_students":   total_students,
                "total_assignments": total_assignments,
                "pending_grading":  pending_grading,
            },
            "recent_enrollments": parse_json(recent_enrollments),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
 

@app.get("/instructor/courses", response_model=List[Dict[str, Any]])
async def get_instructor_courses_fixed(
    current_user: User = Depends(get_instructor_user),
):
    # FIX #8: was calling ObjectId(current_user.id) but current_user.id may already be str
    try:
        inst_oid = ObjectId(str(current_user.id))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")
 
    courses = list(db.courses.find({"instructor_id": inst_oid}))
    for c in courses:
        c.setdefault("title", c.get("name", ""))
        c["enrollment_count"] = db.user_courses.count_documents({
            "course_id": c["_id"], "status": "active"
        })
    return parse_json(courses)



@app.get("/messages/conversations", response_model=Dict[str, Any])
async def get_conversations(
    current_user: User = Depends(get_current_active_user),
):
    """
    Return all conversations for the current user.
    A conversation is modelled as a pair of users who have exchanged messages.
    """
    user_oid = ObjectId(str(current_user.id))
 
    # Distinct chat partners
    sent_to   = db.messages.distinct("recipient_id", {"sender_id": user_oid})
    received  = db.messages.distinct("sender_id",    {"recipient_id": user_oid})
    partner_ids = list({str(u) for u in sent_to + received})
 
    conversations = []
    for pid in partner_ids:
        if not ObjectId.is_valid(pid):
            continue
        partner = db.users.find_one({"_id": ObjectId(pid)})
        if not partner:
            continue
 
        # Last message in the thread
        last_msg = db.messages.find_one(
            {"$or": [
                {"sender_id": user_oid, "recipient_id": ObjectId(pid)},
                {"sender_id": ObjectId(pid), "recipient_id": user_oid},
            ]},
            sort=[("created_at", -1)],
        )
        unread_count = db.messages.count_documents({
            "sender_id":    ObjectId(pid),
            "recipient_id": user_oid,
            "is_read":      False,
        })
 
        conversations.append({
            "id":          pid,
            "name":        f"{partner.get('first_name','')} {partner.get('last_name','')}".strip(),
            "role":        partner.get("role", ""),
            "lastMessage": last_msg.get("text", "") if last_msg else "",
            "unread":      unread_count,
            "updated_at":  last_msg.get("created_at").isoformat() if last_msg and last_msg.get("created_at") else None,
        })
 
    # Sort by most recent message
    conversations.sort(key=lambda c: c.get("updated_at") or "", reverse=True)
    return {"conversations": conversations}



@app.get("/messages/conversations/{partner_id}", response_model=Dict[str, Any])
async def get_conversation_messages(
    partner_id: str,
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Return all messages between current user and a specific partner, oldest first."""
    if not ObjectId.is_valid(partner_id):
        raise HTTPException(status_code=400, detail="Invalid partner ID")
 
    user_oid    = ObjectId(str(current_user.id))
    partner_oid = ObjectId(partner_id)
 
    msgs = list(
        db.messages.find({
            "$or": [
                {"sender_id": user_oid,    "recipient_id": partner_oid},
                {"sender_id": partner_oid, "recipient_id": user_oid},
            ]
        })
        .sort("created_at", 1)
        .skip(skip)
        .limit(limit)
    )
 
    # Mark incoming messages as read
    db.messages.update_many(
        {"sender_id": partner_oid, "recipient_id": user_oid, "is_read": False},
        {"$set": {"is_read": True}},
    )
 
    formatted = []
    for m in msgs:
        formatted.append({
            "id":         str(m["_id"]),
            "text":       m.get("text", ""),
            "senderId":   str(m.get("sender_id", "")),
            "chatId":     partner_id,
            "timestamp":  m.get("created_at").isoformat() if m.get("created_at") else None,
        })
 
    return {"messages": formatted, "chatId": partner_id}
 
 
@app.post("/messages/send", response_model=Dict[str, Any])
async def send_message(
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    """
    Persist a message. The WebSocket delivers it in real time;
    this endpoint persists it so it survives page reload.
    Body: { recipient_id: str, text: str }
    """
    recipient_id = body.get("recipient_id")
    text         = (body.get("text") or "").strip()
 
    if not recipient_id or not ObjectId.is_valid(recipient_id):
        raise HTTPException(status_code=400, detail="recipient_id required")
    if not text:
        raise HTTPException(status_code=400, detail="text required")
 
    msg = {
        "sender_id":    ObjectId(str(current_user.id)),
        "recipient_id": ObjectId(recipient_id),
        "text":         text,
        "is_read":      False,
        "created_at":   datetime.utcnow(),
    }
    result = db.messages.insert_one(msg)
 
    return {
        "id":        str(result.inserted_id),
        "text":      text,
        "senderId":  str(current_user.id),
        "chatId":    recipient_id,
        "timestamp": msg["created_at"].isoformat(),
    }
 


# ==================== ADMIN USERS ENDPOINTS ====================

@app.get("/admin/users", response_model=Dict[str, Any])
async def get_all_users(
        admin_user: User = Depends(get_admin_user),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        role: Optional[str] = None,
        search: Optional[str] = None
):
    """
    Get all users with pagination and filters (admin only)
    """
    try:
        query = {}
        if role:
            query["role"] = role
        if search:
            query["$or"] = [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]

        users = list(db.users.find(query).skip(skip).limit(limit))
        total = db.users.count_documents(query)

        return {
            "users": parse_json(users),
            "total": total,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/users/{user_id}", response_model=Dict[str, Any])
async def get_user_by_id(
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Get a single user by ID with their courses (admin only)
    """
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get user's courses
        user_courses = list(db.user_courses.find({"user_id": ObjectId(user_id)}))
        course_ids = [uc["course_id"] for uc in user_courses]
        courses = list(db.courses.find({"_id": {"$in": course_ids}}))

        user["courses"] = parse_json(courses)

        return parse_json(user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/users", response_model=UserResponse)
async def create_user(
        user: UserCreate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Create a new user (admin only)
    """
    try:
        existing = db.users.find_one({"email": user.email})
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        hashed_password = get_password_hash(user.password)
        user_data = user.dict()
        user_data.pop("password")
        user_data["hashed_password"] = hashed_password
        user_data["created_at"] = datetime.utcnow()
        user_data["updated_at"] = datetime.utcnow()
        user_data["disabled"] = False

        result = db.users.insert_one(user_data)
        created_user = db.users.find_one({"_id": result.inserted_id})

        return parse_json(created_user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/users/{user_id}", response_model=UserResponse)
async def update_user(
        user_id: str,
        user_update: UserUpdate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Update a user (admin only)
    """
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        existing = db.users.find_one({"_id": ObjectId(user_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")

        update_data = user_update.dict(exclude_unset=True)

        if "password" in update_data:
            update_data["hashed_password"] = get_password_hash(update_data.pop("password"))

        update_data["updated_at"] = datetime.utcnow()

        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )

        updated_user = db.users.find_one({"_id": ObjectId(user_id)})
        return parse_json(updated_user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete a user (admin only)
    """
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")

        existing = db.users.find_one({"_id": ObjectId(user_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent self-deletion
        if str(existing["_id"]) == str(admin_user.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )

        db.users.delete_one({"_id": ObjectId(user_id)})
        db.user_courses.delete_many({"user_id": ObjectId(user_id)})
        db.progress.delete_many({"user_id": ObjectId(user_id)})

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/admin/enrollments/pending", response_model=Dict[str, Any])
async def get_pending_enrollments(
    admin_user: User = Depends(get_admin_user),
    course_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    All pending student applications waiting for admin approval.
    """
    query: dict = {"status": "pending"}
    if course_id and ObjectId.is_valid(course_id):
        query["course_id"] = ObjectId(course_id)
 
    pipeline = [
        {"$match": query},
        {"$sort": {"created_at": 1}},
        {"$skip": skip},
        {"$limit": limit},
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "student"}},
        {"$lookup": {"from": "courses", "localField": "course_id", "foreignField": "_id", "as": "course"}},
        {"$unwind": {"path": "$student", "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$course", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "status": 1, "created_at": 1, "note": 1,
            "student_id": "$student._id",
            "student_name": {"$concat": ["$student.first_name", " ", "$student.last_name"]},
            "student_email": "$student.email",
            "course_name": "$course.name",
            "course_id": 1,
        }},
    ]
    results = list(db.user_courses.aggregate(pipeline))
    total = db.user_courses.count_documents(query)
    return {"enrollments": parse_json(results), "total": total}



@app.post("/admin/enrollments/{enrollment_id}/approve", response_model=Dict[str, Any])
async def approve_enrollment(
    enrollment_id: str,
    body: dict = {},
    admin_user: User = Depends(get_admin_user)
):
    """
    Mark a pending application as approved.
    Student is not yet active — admin still needs to assign them to a class.
    Body: { note?: str }
    """
    if not ObjectId.is_valid(enrollment_id):
        raise HTTPException(status_code=400, detail="Invalid enrollment ID")
 
    rec = db.user_courses.find_one({"_id": ObjectId(enrollment_id)})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    if rec["status"] not in ("pending",):
        raise HTTPException(status_code=400, detail=f"Cannot approve — current status: {rec['status']}")
 
    db.user_courses.update_one(
        {"_id": ObjectId(enrollment_id)},
        {"$set": {
            "status": "approved",
            "approved_at": datetime.utcnow(),
            "approved_by": ObjectId(admin_user.id),
            "admin_note": body.get("note", ""),
        }}
    )
    return {"message": "Student approved. Assign them to a class to make active.", "enrollment_id": enrollment_id}


@app.post("/admin/enrollments/{enrollment_id}/reject", response_model=Dict[str, Any])
async def reject_enrollment(
    enrollment_id: str,
    body: dict = {},
    admin_user: User = Depends(get_admin_user)
):
    """
    Reject a pending application.
    Body: { reason?: str }
    """
    if not ObjectId.is_valid(enrollment_id):
        raise HTTPException(status_code=400, detail="Invalid enrollment ID")
 
    rec = db.user_courses.find_one({"_id": ObjectId(enrollment_id)})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")
 
    db.user_courses.update_one(
        {"_id": ObjectId(enrollment_id)},
        {"$set": {
            "status": "rejected",
            "rejected_at": datetime.utcnow(),
            "rejected_by": ObjectId(admin_user.id),
            "rejection_reason": body.get("reason", ""),
        }}
    )
    return {"message": "Student rejected.", "enrollment_id": enrollment_id}


@app.post("/admin/enrollments/assign", response_model=Dict[str, Any])
async def assign_student(
    body: dict,
    admin_user: User = Depends(get_admin_user)
):
    """
    Assign an approved (or directly a new) student to a specific course + class.
    This is the action that makes them fully active.
 
    Body: {
        user_id: str,
        course_id: str,
        class_id: str,
        note?: str          # message to student
    }
    """
    user_id  = body.get("user_id")
    course_id = body.get("course_id")
    class_id  = body.get("class_id")
 
    for field, val in [("user_id", user_id), ("course_id", course_id), ("class_id", class_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required and must be valid")
 
    user_oid   = ObjectId(user_id)
    course_oid = ObjectId(course_id)
    class_oid  = ObjectId(class_id)
 
    # Validate all three objects exist
    if not db.users.find_one({"_id": user_oid}):
        raise HTTPException(status_code=404, detail="Student not found")
    if not db.courses.find_one({"_id": course_oid}):
        raise HTTPException(status_code=404, detail="Course not found")
    if not db.classes.find_one({"_id": class_oid}):
        raise HTTPException(status_code=404, detail="Class not found")
 
    now = datetime.utcnow()
 
    # Upsert: create or update whatever record exists for this user+course
    db.user_courses.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$set": {
            "class_id": class_oid,
            "status": "active",
            "enrolled_at": now,
            "approved_by": ObjectId(admin_user.id),
            "admin_note": body.get("note", ""),
            "updated_at": now,
        },
        "$setOnInsert": {"created_at": now}},
        upsert=True,
    )
 
    # Add student to class.students array (keep class roster in sync)
    db.classes.update_one(
        {"_id": class_oid},
        {"$addToSet": {"students": user_oid}}
    )
 
    # Seed progress doc
    db.progress.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$setOnInsert": {
            "user_id": user_oid,
            "course_id": course_oid,
            "completed_lesson_ids": [],
            "percentage": 0,
            "last_active": now,
        }},
        upsert=True,
    )
 
    return {
        "message": "Student assigned and activated.",
        "user_id": user_id,
        "course_id": course_id,
        "class_id": class_id,
    }


@app.post("/admin/enrollments/reassign", response_model=Dict[str, Any])
async def reassign_student(
    body: dict,
    admin_user: User = Depends(get_admin_user)
):
    """
    Move a student from their current class to a new class (same course).
    Removes from old class roster, adds to new.
 
    Body: {
        user_id: str,
        course_id: str,
        new_class_id: str,
        reason?: str
    }
    """
    user_id      = body.get("user_id")
    course_id    = body.get("course_id")
    new_class_id = body.get("new_class_id")
 
    for field, val in [("user_id", user_id), ("course_id", course_id), ("new_class_id", new_class_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required")
 
    user_oid      = ObjectId(user_id)
    course_oid    = ObjectId(course_id)
    new_class_oid = ObjectId(new_class_id)
 
    rec = db.user_courses.find_one({"user_id": user_oid, "course_id": course_oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    if rec.get("status") != "active":
        raise HTTPException(status_code=400, detail="Student is not currently active in this course")
    if not db.classes.find_one({"_id": new_class_oid}):
        raise HTTPException(status_code=404, detail="New class not found")
 
    old_class_oid = rec.get("class_id")
 
    # Remove from old class roster
    if old_class_oid:
        db.classes.update_one(
            {"_id": old_class_oid},
            {"$pull": {"students": user_oid}}
        )
 
    # Add to new class roster
    db.classes.update_one(
        {"_id": new_class_oid},
        {"$addToSet": {"students": user_oid}}
    )
 
    # Update enrollment record
    db.user_courses.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$set": {
            "class_id": new_class_oid,
            "reassigned_at": datetime.utcnow(),
            "reassigned_by": ObjectId(admin_user.id),
            "reassign_reason": body.get("reason", ""),
        }}
    )
 
    return {
        "message": "Student reassigned successfully.",
        "user_id": user_id,
        "course_id": course_id,
        "new_class_id": new_class_id,
        "old_class_id": str(old_class_oid) if old_class_oid else None,
    }


@app.post("/admin/enrollments/remove", response_model=Dict[str, Any])
async def remove_student_from_class(
    body: dict,
    admin_user: User = Depends(get_admin_user)
):
    """
    Remove a student from a class (and optionally the entire course).
    Their progress is preserved but they lose access immediately.
 
    Body: {
        user_id: str,
        course_id: str,
        remove_from_course?: bool   # default False — removes class only
        reason?: str
    }
    """
    user_id   = body.get("user_id")
    course_id = body.get("course_id")
 
    for field, val in [("user_id", user_id), ("course_id", course_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required")
 
    user_oid   = ObjectId(user_id)
    course_oid = ObjectId(course_id)
 
    rec = db.user_courses.find_one({"user_id": user_oid, "course_id": course_oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")
 
    old_class_oid = rec.get("class_id")
    remove_course = body.get("remove_from_course", False)
 
    # Remove from class roster
    if old_class_oid:
        db.classes.update_one(
            {"_id": old_class_oid},
            {"$pull": {"students": user_oid}}
        )
 
    if remove_course:
        # Full removal from course
        db.user_courses.update_one(
            {"user_id": user_oid, "course_id": course_oid},
            {"$set": {
                "status": "removed",
                "class_id": None,
                "removed_at": datetime.utcnow(),
                "removed_by": ObjectId(admin_user.id),
                "removal_reason": body.get("reason", ""),
            }}
        )
        msg = "Student removed from course."
    else:
        # Remove from class only, keep enrollment as approved (can be reassigned)
        db.user_courses.update_one(
            {"user_id": user_oid, "course_id": course_oid},
            {"$set": {
                "status": "approved",   # back to approved — awaiting class assignment
                "class_id": None,
                "removed_from_class_at": datetime.utcnow(),
                "removal_reason": body.get("reason", ""),
            }}
        )
        msg = "Student removed from class. They remain enrolled — assign a new class."
 
    return {"message": msg, "user_id": user_id, "course_id": course_id}


@app.get("/admin/enrollments", response_model=Dict[str, Any])
async def list_all_enrollments(
    admin_user: User = Depends(get_admin_user),
    status: Optional[str] = None,           # pending|approved|active|rejected|removed
    course_id: Optional[str] = None,
    class_id: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    Master enrollment list for admin — all statuses, all filters.
    """
    match: dict = {}
    if status:
        match["status"] = status
    if course_id and ObjectId.is_valid(course_id):
        match["course_id"] = ObjectId(course_id)
    if class_id and ObjectId.is_valid(class_id):
        match["class_id"] = ObjectId(class_id)
 
    pipeline = [
        {"$match": match},
        {"$sort": {"created_at": -1}},
        {"$lookup": {"from": "users",   "localField": "user_id",   "foreignField": "_id", "as": "student"}},
        {"$lookup": {"from": "courses", "localField": "course_id", "foreignField": "_id", "as": "course"}},
        {"$lookup": {"from": "classes", "localField": "class_id",  "foreignField": "_id", "as": "class"}},
        {"$unwind": {"path": "$student", "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$course",  "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$class",   "preserveNullAndEmptyArrays": True}},
    ]
 
    # Search filter applied after join
    if search:
        pipeline.append({"$match": {"$or": [
            {"student.first_name": {"$regex": search, "$options": "i"}},
            {"student.last_name":  {"$regex": search, "$options": "i"}},
            {"student.email":      {"$regex": search, "$options": "i"}},
        ]}})
 
    pipeline += [
        {"$skip": skip},
        {"$limit": limit},
        {"$project": {
            "status": 1,
            "created_at": 1,
            "enrolled_at": 1,
            "approved_at": 1,
            "admin_note": 1,
            "student_id":    "$student._id",
            "student_name":  {"$concat": ["$student.first_name", " ", "$student.last_name"]},
            "student_email": "$student.email",
            "course_name":   "$course.name",
            "course_id":     1,
            "class_title":   "$class.title",
            "class_id":      1,
        }},
    ]
 
    results = list(db.user_courses.aggregate(pipeline))
    total = db.user_courses.count_documents(match)
 
    # Status counts for tab badges
    counts = {
        s: db.user_courses.count_documents({"status": s})
        for s in ("pending", "approved", "active", "rejected", "removed")
    }
 
    return {
        "enrollments": parse_json(results),
        "total": total,
        "counts": counts,
    }


@app.get("/admin/classes/{class_id}/students", response_model=Dict[str, Any])
async def get_class_students(
    class_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """
    All active students in a class, with their progress.
    """
    if not ObjectId.is_valid(class_id):
        raise HTTPException(status_code=400, detail="Invalid class ID")
 
    class_oid = ObjectId(class_id)
    class_doc = db.classes.find_one({"_id": class_oid})
    if not class_doc:
        raise HTTPException(status_code=404, detail="Class not found")
 
    enrollments = list(db.user_courses.find({"class_id": class_oid, "status": "active"}))
    student_ids = [e["user_id"] for e in enrollments]
    students = list(db.users.find({"_id": {"$in": student_ids}}))
 
    result = []
    for s in students:
        enrollment = next((e for e in enrollments if e["user_id"] == s["_id"]), None)
        progress   = db.progress.find_one({"user_id": s["_id"], "course_id": class_doc.get("course_id")})
        result.append({
            "student_id":    str(s["_id"]),
            "name":          f"{s.get('first_name','')} {s.get('last_name','')}".strip(),
            "email":         s.get("email"),
            "phone":         s.get("phone"),
            "enrolled_at":   enrollment.get("enrolled_at").isoformat() if enrollment and enrollment.get("enrolled_at") else None,
            "progress_pct":  progress.get("percentage", 0) if progress else 0,
            "last_active":   progress.get("last_active").isoformat() if progress and progress.get("last_active") else None,
        })
 
    return {
        "class_id": class_id,
        "class_title": class_doc.get("title"),
        "student_count": len(result),
        "students": result,
    }


# ==================== ADMIN COURSES ENDPOINTS ====================

@app.get("/admin/courses", response_model=Dict[str, Any])
async def get_all_courses_v2(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    level: Optional[str] = None,
    search: Optional[str] = None,
):
    """All courses for admin — with name/title normalised."""
    try:
        query: dict = {}
        if level:
            query["level"] = level
        if search:
            query["$or"] = [
                {"name":        {"$regex": search, "$options": "i"}},
                {"title":       {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
            ]
 
        courses = list(db.courses.find(query).skip(skip).limit(limit))
        total   = db.courses.count_documents(query)
 
        for course in courses:
            # BUG 10 FIX: ensure both name and title always present
            course.setdefault("title", course.get("name", ""))
            course.setdefault("name",  course.get("title", ""))
 
            if course.get("instructor_id"):
                inst = db.users.find_one({"_id": course["instructor_id"]})
                if inst:
                    course["instructor"] = {
                        "id":    str(inst["_id"]),
                        "name":  f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                        "email": inst.get("email", ""),
                    }
 
            course["enrollment_count"] = db.user_courses.count_documents({
                "course_id": course["_id"], "status": "active"
            })
 
        return {"courses": parse_json(courses), "total": total, "skip": skip, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/courses/{course_id}", response_model=Dict[str, Any])
async def get_course_by_id(
        course_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Get a single course by ID with all details (admin only)
    """
    try:
        if not ObjectId.is_valid(course_id):
            raise HTTPException(status_code=400, detail="Invalid course ID")

        course = db.courses.find_one({"_id": ObjectId(course_id)})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")

        # Get instructor
        if course.get("instructor_id"):
            instructor = db.users.find_one({"_id": course["instructor_id"]})
            if instructor:
                course["instructor"] = {
                    "id": str(instructor["_id"]),
                    "name": f"{instructor.get('first_name', '')} {instructor.get('last_name', '')}",
                    "email": instructor.get("email", "")
                }

        # Get students
        enrollments = list(db.user_courses.find({"course_id": ObjectId(course_id)}))
        student_ids = [e["user_id"] for e in enrollments]
        students = list(db.users.find({"_id": {"$in": student_ids}}))

        formatted_students = []
        for student in students:
            enrollment = next((e for e in enrollments if e["user_id"] == student["_id"]), None)
            formatted_students.append({
                "id": str(student["_id"]),
                "name": f"{student.get('first_name', '')} {student.get('last_name', '')}",
                "email": student.get("email", ""),
                "enrollment_date": enrollment.get("enrolled_at") if enrollment else None
            })
        course["students"] = formatted_students

        # Get classes
        classes = list(db.classes.find({"course_id": ObjectId(course_id)}).sort("date", 1))
        course["classes"] = parse_json(classes)

        # Get assignments
        assignments = list(db.assignments.find({"course_id": ObjectId(course_id)}).sort("due_date", 1))
        course["assignments"] = parse_json(assignments)

        return parse_json(course)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/courses", response_model=Dict[str, Any])
async def admin_create_course(
    body: dict,
    admin_user: User = Depends(get_admin_user),
):
    # FIX #7: CourseForm sends both 'name' and 'title' — store both
    if "title" in body and "name" not in body:
        body["name"] = body["title"]
    if "name" in body and "title" not in body:
        body["title"] = body["name"]
 
    body["created_at"] = datetime.utcnow()
    body["updated_at"] = datetime.utcnow()
 
    if body.get("instructor_id") and ObjectId.is_valid(body["instructor_id"]):
        body["instructor_id"] = ObjectId(body["instructor_id"])
 
    # Convert price/duration to correct types
    if "price"    in body: body["price"]    = float(body["price"]    or 0)
    if "duration" in body: body["duration"] = int(body["duration"]   or 0)
 
    result  = db.courses.insert_one(body)
    created = db.courses.find_one({"_id": result.inserted_id})
    return parse_json(created)


@app.put("/admin/courses/{course_id}", response_model=Dict[str, Any])
async def admin_update_course(
    course_id: str,
    body: dict,
    admin_user: User = Depends(get_admin_user),
):
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
 
    # FIX #7: keep name/title in sync
    if "title" in body and "name" not in body:
        body["name"] = body["title"]
    if "name" in body and "title" not in body:
        body["title"] = body["name"]
 
    body.pop("_id", None)
    body["updated_at"] = datetime.utcnow()
 
    if body.get("instructor_id") and ObjectId.is_valid(str(body["instructor_id"])):
        body["instructor_id"] = ObjectId(body["instructor_id"])
 
    db.courses.update_one({"_id": ObjectId(course_id)}, {"$set": body})
    updated = db.courses.find_one({"_id": ObjectId(course_id)})
    if not updated:
        raise HTTPException(status_code=404, detail="Course not found")
    updated.setdefault("title", updated.get("name", ""))
    return parse_json(updated)

@app.delete("/admin/courses/{course_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_course(
        course_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete a course and all related data (admin only)
    """
    try:
        if not ObjectId.is_valid(course_id):
            raise HTTPException(status_code=400, detail="Invalid course ID")

        existing = db.courses.find_one({"_id": ObjectId(course_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Course not found")

        db.courses.delete_one({"_id": ObjectId(course_id)})
        db.user_courses.delete_many({"course_id": ObjectId(course_id)})
        db.classes.delete_many({"course_id": ObjectId(course_id)})
        db.assignments.delete_many({"course_id": ObjectId(course_id)})
        db.progress.delete_many({"course_id": ObjectId(course_id)})

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/courses/{course_id}/enroll/{user_id}", status_code=status.HTTP_200_OK)
async def enroll_user_in_course(
        course_id: str,
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Enroll a user in a course (admin only)
    """
    try:
        if not ObjectId.is_valid(course_id) or not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid ID format")

        course = db.courses.find_one({"_id": ObjectId(course_id)})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")

        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        existing = db.user_courses.find_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id)
        })

        if existing:
            return {"message": "User already enrolled in this course"}

        enrollment = {
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id),
            "enrolled_at": datetime.utcnow(),
            "status": "active"
        }
        db.user_courses.insert_one(enrollment)

        progress = {
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id),
            "percentage": 0,
            "modules_completed": [],
            "last_activity": datetime.utcnow()
        }
        db.progress.insert_one(progress)

        return {"message": "User successfully enrolled in course"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/courses/{course_id}/enroll/{user_id}", status_code=status.HTTP_200_OK)
async def remove_user_from_course(
        course_id: str,
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Remove a user from a course (admin only)
    """
    try:
        if not ObjectId.is_valid(course_id) or not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid ID format")

        enrollment = db.user_courses.find_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id)
        })

        if not enrollment:
            raise HTTPException(status_code=404, detail="Enrollment not found")

        db.user_courses.delete_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id)
        })

        db.progress.delete_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id)
        })

        return {"message": "User successfully removed from course"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== ADMISSION INQUIRIES ADMIN ====================

@app.get("/admin/admission-inquiries", response_model=Dict[str, Any])
async def get_admission_inquiries(
        admin_user: User = Depends(get_admin_user),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        status: Optional[str] = None,
        program: Optional[str] = None,
        location: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: int = -1
):
    """
    Get all admission inquiries with pagination and filters (admin only)
    """
    try:
        query = {}
        
        if status:
            query["status"] = status
        if program:
            query["program"] = program
        if location:
            query["location"] = location
        if search:
            query["$or"] = [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
                {"phone": {"$regex": search, "$options": "i"}}
            ]

        inquiries = list(db.admission_inquiries.find(query)
                        .sort(sort_by, sort_order)
                        .skip(skip)
                        .limit(limit))

        total = db.admission_inquiries.count_documents(query)

        # Get statistics
        status_stats = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))

        program_stats = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$program", "count": {"$sum": 1}}}
        ]))

        location_stats = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$location", "count": {"$sum": 1}}}
        ]))

        return {
            "inquiries": parse_json(inquiries),
            "pagination": {
                "total": total,
                "skip": skip,
                "limit": limit,
                "has_more": skip + limit < total
            },
            "statistics": {
                "by_status": parse_json(status_stats),
                "by_program": parse_json(program_stats),
                "by_location": parse_json(location_stats)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/admission-inquiries/{inquiry_id}", response_model=Dict[str, Any])
async def get_admission_inquiry(
        inquiry_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Get a single admission inquiry by ID (admin only)
    """
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")

        inquiry = db.admission_inquiries.find_one({"_id": ObjectId(inquiry_id)})
        if not inquiry:
            raise HTTPException(status_code=404, detail="Inquiry not found")

        # Mark as read
        db.admission_inquiries.update_one(
            {"_id": ObjectId(inquiry_id)},
            {"$set": {"is_read": True}}
        )

        return parse_json(inquiry)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/admission-inquiries/{inquiry_id}/status", status_code=status.HTTP_200_OK)
async def update_inquiry_status(
        inquiry_id: str,
        status_data: dict,
        admin_user: User = Depends(get_admin_user)
):
    """
    Update the status of an admission inquiry (admin only)
    Status can be: pending, contacted, enrolled
    """
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")

        new_status = status_data.get("status")
        if not new_status or new_status not in ["pending", "contacted", "enrolled"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status. Must be one of: pending, contacted, enrolled"
            )

        result = db.admission_inquiries.update_one(
            {"_id": ObjectId(inquiry_id)},
            {
                "$set": {
                    "status": new_status,
                    "updated_at": datetime.utcnow()
                }
            }
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")

        return {"message": f"Inquiry status updated to {new_status}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/admission-inquiries/{inquiry_id}/notes", status_code=status.HTTP_200_OK)
async def add_inquiry_note(
        inquiry_id: str,
        note_data: dict,
        admin_user: User = Depends(get_admin_user)
):
    """
    Add an admin note to an inquiry (admin only)
    """
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")

        note = note_data.get("note")
        if not note:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Note is required"
            )

        note_obj = {
            "note": note,
            "created_by": str(admin_user.id),
            "created_by_name": f"{admin_user.first_name} {admin_user.last_name}",
            "created_at": datetime.utcnow()
        }

        result = db.admission_inquiries.update_one(
            {"_id": ObjectId(inquiry_id)},
            {
                "$push": {"admin_notes": note_obj},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")

        return {"message": "Note added successfully", "note": note_obj}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/admission-inquiries/{inquiry_id}", status_code=status.HTTP_200_OK)
async def delete_admission_inquiry(
        inquiry_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete an admission inquiry (admin only)
    """
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")

        result = db.admission_inquiries.delete_one({"_id": ObjectId(inquiry_id)})

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")

        return {"success": True, "message": "Inquiry deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/admission-inquiries/stats/summary", response_model=Dict[str, Any])
async def get_admission_stats(
        admin_user: User = Depends(get_admin_user)
):
    """
    Get summary statistics for admission inquiries (admin only)
    """
    try:
        total = db.admission_inquiries.count_documents({})
        unread = db.admission_inquiries.count_documents({"is_read": False})
        
        status_counts = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))
        
        program_counts = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$program", "count": {"$sum": 1}}}
        ]))
        
        location_counts = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$location", "count": {"$sum": 1}}}
        ]))
        
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent = db.admission_inquiries.count_documents({
            "created_at": {"$gte": thirty_days_ago}
        })
        
        daily = list(db.admission_inquiries.aggregate([
            {"$match": {"created_at": {"$gte": thirty_days_ago}}},
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$created_at"},
                        "month": {"$month": "$created_at"},
                        "day": {"$dayOfMonth": "$created_at"}
                    },
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1}}
        ]))

        return {
            "total": total,
            "unread": unread,
            "recent_30_days": recent,
            "by_status": parse_json(status_counts),
            "by_program": parse_json(program_counts),
            "by_location": parse_json(location_counts),
            "daily_trend": parse_json(daily)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/admission-inquiries/export/csv")
async def export_inquiries_csv(
        admin_user: User = Depends(get_admin_user)
):
    """
    Export all admission inquiries as CSV (admin only)
    """
    try:
        inquiries = list(db.admission_inquiries.find().sort("created_at", -1))
        
        output = StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            "First Name", "Last Name", "Email", "Phone", 
            "Program", "Location", "Message", "Status", 
            "Created At", "Read"
        ])
        
        for inquiry in inquiries:
            writer.writerow([
                inquiry.get("first_name", ""),
                inquiry.get("last_name", ""),
                inquiry.get("email", ""),
                inquiry.get("phone", ""),
                inquiry.get("program", ""),
                inquiry.get("location", ""),
                inquiry.get("message", ""),
                inquiry.get("status", "pending"),
                inquiry.get("created_at", ""),
                "Yes" if inquiry.get("is_read") else "No"
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=admission_inquiries.csv"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== JOB ADMIN ENDPOINTS ====================

# ==================== ADMIN CAREERS STATS ====================

@app.get("/admin/careers/stats", response_model=Dict[str, Any])
async def admin_get_careers_stats(admin_user: User = Depends(get_admin_user)):
    """
    Get careers-specific statistics (admin only)
    """
    try:
        # Job statistics
        total_jobs = db.job_listings.count_documents({})
        published_jobs = db.job_listings.count_documents({"is_published": True})
        featured_jobs = db.job_listings.count_documents({"is_featured": True})

        # Application statistics
        total_applications = db.job_applications.count_documents({})
        applications_by_status = list(db.job_applications.aggregate([
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]))

        # Category statistics
        categories = list(db.job_categories.find())
        for category in categories:
            job_count = db.job_listings.count_documents({
                "category": category["name"],
                "is_published": True
            })
            category["job_count"] = job_count

        # Recent activity
        recent_jobs = list(db.job_listings.find().sort("created_at", -1).limit(5))
        recent_applications = list(db.job_applications.find().sort("created_at", -1).limit(5))

        # Add job info to recent applications
        for app in recent_applications:
            job = db.job_listings.find_one({"_id": app["job_id"]})
            if job:
                app["job"] = {
                    "id": str(job["_id"]),
                    "title": job["title"],
                    "company": job["company"]
                }

        # Top viewed jobs
        top_viewed_jobs = list(db.job_listings.find().sort("views", -1).limit(5))

        # Jobs with most applications
        top_applied_jobs = list(db.job_listings.find().sort("applications_count", -1).limit(5))

        return {
            "job_stats": {
                "total": total_jobs,
                "published": published_jobs,
                "featured": featured_jobs
            },
            "application_stats": {
                "total": total_applications,
                "by_status": parse_json(applications_by_status)
            },
            "categories": parse_json(categories),
            "recent_activity": {
                "jobs": parse_json(recent_jobs),
                "applications": parse_json(recent_applications)
            },
            "top_jobs": {
                "by_views": parse_json(top_viewed_jobs),
                "by_applications": parse_json(top_applied_jobs)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/careers/jobs", response_model=Dict[str, Any])
async def admin_get_job_listings(
        admin_user: User = Depends(get_admin_user),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        category: Optional[str] = None,
        is_published: Optional[bool] = None,
        search: Optional[str] = None
):
    """
    Get all job listings for admin management
    """
    try:
        query = {}

        if category:
            query["category"] = category
        if is_published is not None:
            query["is_published"] = is_published
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"company": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}}
            ]

        jobs = list(db.job_listings.find(query)
                    .sort("created_at", -1)
                    .skip(skip)
                    .limit(limit))

        total = db.job_listings.count_documents(query)

        for job in jobs:
            job["applications_count"] = db.job_applications.count_documents({"job_id": job["_id"]})

        return {
            "jobs": parse_json(jobs),
            "total": total,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/careers/jobs", response_model=JobListingResponse)
async def admin_create_job_listing(
        job: JobListingCreate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Create a new job listing (admin only)
    """
    try:
        job_data = job.dict()
        job_data["created_by"] = ObjectId(admin_user.id)
        job_data["created_at"] = datetime.utcnow()
        job_data["updated_at"] = datetime.utcnow()
        job_data["views"] = 0
        job_data["applications_count"] = 0

        result = db.job_listings.insert_one(job_data)
        created_job = db.job_listings.find_one({"_id": result.inserted_id})

        return parse_json(created_job)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/careers/jobs/{job_id}", response_model=JobListingResponse)
async def admin_update_job_listing(
        job_id: str,
        job_update: JobListingUpdate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Update a job listing (admin only)
    """
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        existing = db.job_listings.find_one({"_id": ObjectId(job_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Job listing not found")

        update_data = job_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()

        db.job_listings.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": update_data}
        )

        updated_job = db.job_listings.find_one({"_id": ObjectId(job_id)})
        return parse_json(updated_job)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/careers/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_job_listing(
        job_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete a job listing (admin only)
    """
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        existing = db.job_listings.find_one({"_id": ObjectId(job_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Job listing not found")

        db.job_listings.delete_one({"_id": ObjectId(job_id)})
        db.job_applications.delete_many({"job_id": ObjectId(job_id)})

        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== JOB APPLICATIONS ADMIN ====================

@app.get("/admin/careers/applications", response_model=Dict[str, Any])
async def admin_get_job_applications(
        admin_user: User = Depends(get_admin_user),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        job_id: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
):
    """
    Get all job applications with filters (admin only)
    """
    try:
        query = {}

        if job_id:
            if not ObjectId.is_valid(job_id):
                raise HTTPException(status_code=400, detail="Invalid job ID")
            query["job_id"] = ObjectId(job_id)

        if status:
            query["status"] = status

        if search:
            query["$or"] = [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]

        applications = list(db.job_applications.find(query)
                           .sort("created_at", -1)
                           .skip(skip)
                           .limit(limit))

        total = db.job_applications.count_documents(query)

        for app in applications:
            job = db.job_listings.find_one({"_id": app["job_id"]})
            if job:
                app["job"] = {
                    "id": str(job["_id"]),
                    "title": job["title"],
                    "company": job["company"]
                }

        return {
            "applications": parse_json(applications),
            "total": total,
            "skip": skip,
            "limit": limit
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/careers/applications/{application_id}", response_model=JobApplicationResponse)
async def admin_get_application_details(
        application_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Get detailed job application (admin only)
    """
    try:
        if not ObjectId.is_valid(application_id):
            raise HTTPException(status_code=400, detail="Invalid application ID")

        application = db.job_applications.find_one({"_id": ObjectId(application_id)})
        if not application:
            raise HTTPException(status_code=404, detail="Application not found")

        job = db.job_listings.find_one({"_id": application["job_id"]})
        if job:
            application["job"] = parse_json(job)

        return parse_json(application)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/careers/applications/{application_id}", response_model=JobApplicationResponse)
async def admin_update_application_status(
        application_id: str,
        application_update: JobApplicationUpdate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Update job application status (admin only)
    """
    try:
        if not ObjectId.is_valid(application_id):
            raise HTTPException(status_code=400, detail="Invalid application ID")

        existing = db.job_applications.find_one({"_id": ObjectId(application_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Application not found")

        update_data = application_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()

        db.job_applications.update_one(
            {"_id": ObjectId(application_id)},
            {"$set": update_data}
        )

        updated = db.job_applications.find_one({"_id": ObjectId(application_id)})
        
        job = db.job_listings.find_one({"_id": updated["job_id"]})
        if job:
            updated["job"] = {
                "id": str(job["_id"]),
                "title": job["title"],
                "company": job["company"]
            }

        return parse_json(updated)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== JOB CATEGORIES ADMIN ====================

@app.get("/admin/careers/categories", response_model=List[Dict[str, Any]])
async def admin_get_job_categories(
        admin_user: User = Depends(get_admin_user)
):
    """
    Get all job categories with job counts (admin only)
    """
    try:
        categories = list(db.job_categories.find().sort("name", 1))
        
        for category in categories:
            category["job_count"] = db.job_listings.count_documents({"category": category["name"]})
        
        return parse_json(categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/careers/categories", response_model=JobCategory)
async def admin_create_job_category(
        category: JobCategoryCreate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Create a new job category (admin only)
    """
    try:
        existing = db.job_categories.find_one({"name": category.name})
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Category already exists"
            )

        category_data = category.dict()
        category_data["created_at"] = datetime.utcnow()
        category_data["updated_at"] = datetime.utcnow()
        category_data["job_count"] = 0

        result = db.job_categories.insert_one(category_data)
        created = db.job_categories.find_one({"_id": result.inserted_id})

        return parse_json(created)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/careers/categories/{category_id}", response_model=JobCategory)
async def admin_update_job_category(
        category_id: str,
        category_update: JobCategoryUpdate,
        admin_user: User = Depends(get_admin_user)
):
    """
    Update a job category (admin only)
    """
    try:
        if not ObjectId.is_valid(category_id):
            raise HTTPException(status_code=400, detail="Invalid category ID")

        existing = db.job_categories.find_one({"_id": ObjectId(category_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Category not found")

        update_data = category_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()

        db.job_categories.update_one(
            {"_id": ObjectId(category_id)},
            {"$set": update_data}
        )

        # Update job listings if name changed
        if "name" in update_data and update_data["name"] != existing["name"]:
            db.job_listings.update_many(
                {"category": existing["name"]},
                {"$set": {"category": update_data["name"]}}
            )

        updated = db.job_categories.find_one({"_id": ObjectId(category_id)})
        updated["job_count"] = db.job_listings.count_documents({"category": updated["name"]})

        return parse_json(updated)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/careers/categories/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_job_category(
        category_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete a job category (admin only)
    """
    try:
        if not ObjectId.is_valid(category_id):
            raise HTTPException(status_code=400, detail="Invalid category ID")

        existing = db.job_categories.find_one({"_id": ObjectId(category_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Category not found")

        job_count = db.job_listings.count_documents({"category": existing["name"]})
        if job_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete category with {job_count} job listings. Update or delete the listings first."
            )

        db.job_categories.delete_one({"_id": ObjectId(category_id)})
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== ADMIN DASHBOARD STATS ====================

@app.get("/admin/dashboard/stats", response_model=Dict[str, Any])
async def get_admin_dashboard_stats(
        admin_user: User = Depends(get_admin_user)
):
    """
    Get comprehensive dashboard statistics for admin
    """
    try:
        # User stats
        total_users = db.users.count_documents({})
        active_users = db.users.count_documents({"disabled": False})
        user_roles = list(db.users.aggregate([
            {"$group": {"_id": "$role", "count": {"$sum": 1}}}
        ]))

        # Course stats
        total_courses = db.courses.count_documents({})
        total_enrollments = db.user_courses.count_documents({})
        courses_by_level = list(db.courses.aggregate([
            {"$group": {"_id": "$level", "count": {"$sum": 1}}}
        ]))

        # Blog stats
        total_posts = db.blog_posts.count_documents({})
        posts_by_category = list(db.blog_posts.aggregate([
            {"$group": {"_id": "$category", "count": {"$sum": 1}}}
        ]))
        total_comments = db.comments.count_documents({})

        # Job stats
        total_jobs = db.job_listings.count_documents({})
        total_applications = db.job_applications.count_documents({})
        jobs_by_category = list(db.job_listings.aggregate([
            {"$group": {"_id": "$category", "count": {"$sum": 1}}}
        ]))

        # Contact stats
        total_contacts = db.contact_submissions.count_documents({})
        unread_contacts = db.contact_submissions.count_documents({"is_read": False})

        # Admission stats
        total_inquiries = db.admission_inquiries.count_documents({})
        unread_inquiries = db.admission_inquiries.count_documents({"is_read": False})
        inquiries_by_status = list(db.admission_inquiries.aggregate([
            {"$group": {"_id": "$status", "count": {"$sum": 1}}}
        ]))

        # Recent activity
        recent_users = list(db.users.find().sort("created_at", -1).limit(5))
        recent_applications = list(db.job_applications.find().sort("created_at", -1).limit(5))
        recent_inquiries = list(db.admission_inquiries.find().sort("created_at", -1).limit(5))

        return {
            "users": {
                "total": total_users,
                "active": active_users,
                "by_role": parse_json(user_roles)
            },
            "courses": {
                "total": total_courses,
                "enrollments": total_enrollments,
                "by_level": parse_json(courses_by_level)
            },
            "blog": {
                "total_posts": total_posts,
                "total_comments": total_comments,
                "by_category": parse_json(posts_by_category)
            },
            "careers": {
                "total_jobs": total_jobs,
                "total_applications": total_applications,
                "by_category": parse_json(jobs_by_category)
            },
            "contacts": {
                "total": total_contacts,
                "unread": unread_contacts
            },
            "admissions": {
                "total": total_inquiries,
                "unread": unread_inquiries,
                "by_status": parse_json(inquiries_by_status)
            },
            "recent": {
                "users": parse_json(recent_users),
                "applications": parse_json(recent_applications),
                "inquiries": parse_json(recent_inquiries)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CONTACT SUBMISSIONS ADMIN ====================

@app.get("/admin/contact-submissions/list", response_model=Dict[str, Any])
async def get_all_contact_submissions(
        admin_user: User = Depends(get_admin_user),
        skip: int = Query(0, ge=0),
        limit: int = Query(20, ge=1, le=100),
        read_status: Optional[bool] = None,
        sort_by: str = "created_at",
        sort_order: int = -1
):
    """
    Get all contact form submissions (admin only)
    """
    try:
        query = {}
        if read_status is not None:
            query["is_read"] = read_status

        submissions = list(db.contact_submissions.find(query)
                          .sort(sort_by, sort_order)
                          .skip(skip)
                          .limit(limit))

        total = db.contact_submissions.count_documents(query)

        return {
            "data": parse_json(submissions),
            "pagination": {
                "total": total,
                "skip": skip,
                "limit": limit,
                "has_more": skip + limit < total
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/contact-submissions/{submission_id}", response_model=Dict[str, Any])
async def get_contact_submission_details(
        submission_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Get a single contact form submission (admin only)
    """
    try:
        if not ObjectId.is_valid(submission_id):
            raise HTTPException(status_code=400, detail="Invalid submission ID")

        submission = db.contact_submissions.find_one({"_id": ObjectId(submission_id)})
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")

        # Mark as read
        db.contact_submissions.update_one(
            {"_id": ObjectId(submission_id)},
            {"$set": {"is_read": True}}
        )

        return parse_json(submission)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/contact-submissions/{submission_id}/read", status_code=status.HTTP_200_OK)
async def mark_submission_read(
        submission_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Mark a contact submission as read (admin only)
    """
    try:
        if not ObjectId.is_valid(submission_id):
            raise HTTPException(status_code=400, detail="Invalid submission ID")

        result = db.contact_submissions.update_one(
            {"_id": ObjectId(submission_id)},
            {"$set": {"is_read": True}}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Submission not found")

        return {"success": True, "message": "Submission marked as read"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/contact-submissions/{submission_id}", status_code=status.HTTP_200_OK)
async def delete_submission(
        submission_id: str,
        admin_user: User = Depends(get_admin_user)
):
    """
    Delete a contact form submission (admin only)
    """
    try:
        if not ObjectId.is_valid(submission_id):
            raise HTTPException(status_code=400, detail="Invalid submission ID")

        result = db.contact_submissions.delete_one({"_id": ObjectId(submission_id)})

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Submission not found")

        return {"success": True, "message": "Submission deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
