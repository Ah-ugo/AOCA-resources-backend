from pydantic import BaseModel, Field, EmailStr, GetJsonSchemaHandler, BeforeValidator
from typing import List, Dict, Any, Optional, Annotated
from datetime import datetime
from bson import ObjectId
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, PydanticCustomError, core_schema



# class PyObjectId(ObjectId):
#     @classmethod
#     def __get_validators__(cls):
#         yield cls.validate
#
#     @classmethod
#     def validate(cls, v):
#         if not isinstance(v, ObjectId):
#             raise ValueError("Not a valid ObjectId")
#         return str(v)

def validate_objectid(value: str) -> str:
    if not ObjectId.is_valid(value):
        raise ValueError("Invalid ObjectId")
    return value

PyObjectId = Annotated[str, BeforeValidator(validate_objectid)]

# User models
class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None
    bio: Optional[str] = None
    image: Optional[str] = None
    role: Optional[str] = "student"  # Default role is student


class UserCreate(UserBase):
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class User(UserBase):
    id: Optional[PyObjectId] = Field(alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    disabled: Optional[bool] = False

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


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
    password: Optional[str] = None  # For password updates
    disabled: Optional[bool] = None


class UserResponse(User):
    courses: Optional[List[Dict[str, Any]]] = []


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
    id: Optional[PyObjectId] = Field(alias="_id")
    author_id: Optional[PyObjectId] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


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
    id: Optional[PyObjectId] = Field(alias="_id")
    post_id: Optional[PyObjectId] = None
    user_id: Optional[PyObjectId] = None
    user_name: Optional[str] = None
    user_image: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


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
    employment_type: str  # full-time, part-time, contract, internship
    category: str  # engineering, marketing, sales, etc.
    experience_level: str  # entry, mid, senior
    education: Optional[str] = None
    skills: List[str]
    benefits: Optional[List[str]] = []
    application_url: Optional[str] = None  # External application URL if any
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
    id: Optional[PyObjectId] = Field(alias="_id")
    created_by: Optional[PyObjectId] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    views: int = 0
    applications_count: int = 0

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }

class JobListingResponse(JobListing):
    created_by_user: Optional[Dict[str, Any]] = None

class JobApplicationBase(BaseModel):
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
    status: Optional[str] = None  # applied, reviewed, interview, rejected, hired
    admin_notes: Optional[str] = None
    interview_date: Optional[datetime] = None

class JobApplication(JobApplicationBase):
    id: Optional[PyObjectId] = Field(alias="_id")
    user_id: PyObjectId
    job_id: PyObjectId
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    status: str = "applied"  # applied, reviewed, interview, rejected, hired
    admin_notes: Optional[str] = None
    interview_date: Optional[datetime] = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }

class JobApplicationResponse(JobApplication):
    user: Optional[Dict[str, Any]] = None
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
    id: Optional[PyObjectId] = Field(alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    job_count: int = 0

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


# Course models
class CourseBase(BaseModel):
    name: str
    description: str
    level: str  # A1, A2, B1, etc.
    duration: int  # in weeks
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
    id: Optional[PyObjectId] = Field(alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


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
    id: Optional[PyObjectId] = Field(alias="_id")
    course_id: PyObjectId
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    submissions: Optional[List[Dict[str, Any]]] = []

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


class AssignmentResponse(Assignment):
    course: Optional[Dict[str, Any]] = None
    submission_count: Optional[int] = 0


# Class models
class ClassBase(BaseModel):
    course_id: str
    title: str
    description: str
    date: datetime
    duration: int  # in minutes
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
    id: Optional[PyObjectId] = Field(alias="_id")
    course_id: PyObjectId
    instructor_id: Optional[PyObjectId] = None
    course: Optional[Dict[str, Any]] = None
    instructor: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
    }


# Resource models
class ResourceBase(BaseModel):
    title: str
    description: str
    type: str  # document, video, audio, interactive
    url: str
    level: str  # A1, A2, B1, etc.
    category: str  # grammar, vocabulary, pronunciation, etc.


class ResourceCreate(ResourceBase):
    pass


class ResourceUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    level: Optional[str] = None
    category: Optional[str] = None


# class ResourceResponse(ResourceBase):
#     id: Optional[PyObjectId] = Field(alias="_id")
#     created_at: Optional[datetime] = None
#     updated_at: Optional[datetime] = None
#     created_by: Optional[PyObjectId] = None
#
#     model_config = {
#         "arbitrary_types_allowed": True,
#         "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()}
#     }

class ResourceResponse(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[PyObjectId] = None

    model_config = {
        "arbitrary_types_allowed": True
    }

    @staticmethod
    def serialize(obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj


class ContactForm(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    service: str
    message: str