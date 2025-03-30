from fastapi import FastAPI, Depends, HTTPException, status, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import jwt
from passlib.context import CryptContext
import cloudinary
import cloudinary.uploader
from pymongo import MongoClient
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr
import json
from models import (
    UserCreate, User, UserInDB, UserLogin, Token, TokenData,
    UserUpdate, UserResponse,
    BlogPostCreate, BlogPost, BlogPostUpdate, BlogPostResponse,
    CourseCreate, Course, CourseUpdate, CourseResponse,
    ClassCreate, ClassUpdate, ClassResponse,
    AssignmentCreate, Assignment, AssignmentUpdate, AssignmentResponse,
    CommentCreate, Comment,
    ResourceCreate, ResourceUpdate, ResourceResponse
)

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="AOCA Resources API", description="API for AOCA Resources Limited website")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure MongoDB connection
MONGO_URI = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client["aoca_resources"]

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET")
)

# Configure JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 3000

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(email: str):
    user = db.users.find_one({"email": email})
    if user:
        # Convert ObjectId to string
        user["_id"] = str(user["_id"])  # Ensure _id is converted to string
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
        expire = datetime.utcnow() + timedelta(minutes=15)
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


# Admin authorization check
async def get_admin_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user


# Helper function to convert ObjectId to string
def parse_json(data):
    return json.loads(json.dumps(data, default=str))


# Authentication endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
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
    user_data["role"] = user_data.get("role", "student")  # Default role is student

    # Insert into database
    result = db.users.insert_one(user_data)

    # Return user data
    created_user = db.users.find_one({"_id": result.inserted_id})
    return parse_json(created_user)


# Blog endpoints
@app.get("/blog/posts", response_model=Dict[str, Any])
async def get_blog_posts(
        skip: int = 0,
        limit: int = 10,
        category: Optional[str] = None,
        search: Optional[str] = None
):
    # Build query
    query = {}
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"excerpt": {"$regex": search, "$options": "i"}},
            {"content": {"$regex": search, "$options": "i"}}
        ]

    # Get posts
    posts = list(db.blog_posts.find(query).sort("created_at", -1).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.blog_posts.count_documents(query)

    # Format response
    for post in posts:
        # Get author details
        if "author_id" in post and post["author_id"]:
            author = db.users.find_one({"_id": post["author_id"]})
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


@app.get("/blog/posts/{post_id}", response_model=Dict[str, Any])
async def get_blog_post(post_id: str):
    try:
        post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        # Get author details
        if "author_id" in post and post["author_id"]:
            author = db.users.find_one({"_id": post["author_id"]})
            if author:
                post["author"] = {
                    "name": f"{author.get('first_name', '')} {author.get('last_name', '')}",
                    "role": author.get("role", ""),
                    "image": author.get("image", "")
                }

        # Get comments
        comments = list(db.comments.find({"post_id": ObjectId(post_id)}).sort("created_at", -1))
        post["comments"] = parse_json(comments)

        # Get related posts (same category)
        related_posts = list(db.blog_posts.find({
            "category": post["category"],
            "_id": {"$ne": ObjectId(post_id)}
        }).limit(3))
        post["related_posts"] = parse_json(related_posts)

        return parse_json(post)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/blog/posts", response_model=BlogPostResponse)
async def create_blog_post(
        post: BlogPostCreate,
        current_user: User = Depends(get_current_active_user)
):
    # Check if user has permission
    if current_user.role not in ["admin", "editor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    # Prepare post data
    post_data = post.dict()
    post_data["author_id"] = ObjectId(current_user.id)
    post_data["created_at"] = datetime.utcnow()
    post_data["updated_at"] = datetime.utcnow()

    # Insert into database
    result = db.blog_posts.insert_one(post_data)

    # Return created post
    created_post = db.blog_posts.find_one({"_id": result.inserted_id})
    return parse_json(created_post)


@app.put("/blog/posts/{post_id}", response_model=BlogPostResponse)
async def update_blog_post(
        post_id: str,
        post_update: BlogPostUpdate,
        current_user: User = Depends(get_current_active_user)
):
    # Check if user has permission
    if current_user.role not in ["admin", "editor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    # Check if post exists
    existing_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
    if not existing_post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Update post
    update_data = post_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    db.blog_posts.update_one(
        {"_id": ObjectId(post_id)},
        {"$set": update_data}
    )

    # Return updated post
    updated_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
    return parse_json(updated_post)


@app.delete("/blog/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blog_post(
        post_id: str,
        current_user: User = Depends(get_current_active_user)
):
    # Check if user has permission
    if current_user.role not in ["admin", "editor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    # Check if post exists
    existing_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
    if not existing_post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Delete post
    db.blog_posts.delete_one({"_id": ObjectId(post_id)})

    # Delete associated comments
    db.comments.delete_many({"post_id": ObjectId(post_id)})

    return None


@app.post("/blog/posts/{post_id}/comments", response_model=Comment)
async def add_comment(
        post_id: str,
        comment: CommentCreate,
        current_user: Optional[User] = Depends(get_current_user)
):
    # Check if post exists
    post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # Prepare comment data
    comment_data = comment.dict()
    comment_data["post_id"] = ObjectId(post_id)
    comment_data["created_at"] = datetime.utcnow()

    # Add user info if authenticated
    if current_user:
        comment_data["user_id"] = ObjectId(current_user.id)
        comment_data["user_name"] = f"{current_user.first_name} {current_user.last_name}"
        comment_data["user_image"] = current_user.image

    # Insert into database
    result = db.comments.insert_one(comment_data)

    # Return created comment
    created_comment = db.comments.find_one({"_id": result.inserted_id})
    return parse_json(created_comment)


# Dashboard endpoints
@app.get("/dashboard/overview", response_model=Dict[str, Any])
async def get_dashboard_overview(current_user: User = Depends(get_current_active_user)):
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

    # Calculate course progress
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


@app.get("/dashboard/courses", response_model=List[Dict[str, Any]])
async def get_user_courses(current_user: User = Depends(get_current_active_user)):
    # Get user's courses
    user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
    course_ids = [uc["course_id"] for uc in user_courses]

    # Get course details
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))

    # Calculate progress for each course
    for course in courses:
        progress = db.progress.find_one({
            "user_id": ObjectId(current_user.id),
            "course_id": course["_id"]
        })
        course["progress"] = progress["percentage"] if progress else 0

    return parse_json(courses)


@app.get("/dashboard/assignments", response_model=List[Dict[str, Any]])
async def get_user_assignments(
        current_user: User = Depends(get_current_active_user),
        status: Optional[str] = None
):
    # Get user's courses
    user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
    course_ids = [uc["course_id"] for uc in user_courses]

    # Build query
    query = {"course_id": {"$in": course_ids}}

    if status == "pending":
        query["submissions.user_id"] = {"$ne": ObjectId(current_user.id)}
        query["due_date"] = {"$gte": datetime.utcnow()}
    elif status == "completed":
        query["submissions.user_id"] = ObjectId(current_user.id)
    elif status == "overdue":
        query["submissions.user_id"] = {"$ne": ObjectId(current_user.id)}
        query["due_date"] = {"$lt": datetime.utcnow()}

    # Get assignments
    assignments = list(db.assignments.find(query).sort("due_date", 1))

    # Add course info to each assignment
    for assignment in assignments:
        course = db.courses.find_one({"_id": assignment["course_id"]})
        if course:
            assignment["course"] = {
                "id": str(course["_id"]),
                "name": course["name"],
                "level": course["level"]
            }

    return parse_json(assignments)


@app.get("/dashboard/classes", response_model=List[Dict[str, Any]])
async def get_user_classes(
        current_user: User = Depends(get_current_active_user),
        upcoming: bool = True
):
    # Get user's courses
    user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
    course_ids = [uc["course_id"] for uc in user_courses]

    # Build query
    query = {"course_id": {"$in": course_ids}}

    if upcoming:
        query["date"] = {"$gte": datetime.utcnow()}
        sort_direction = 1  # Ascending for upcoming
    else:
        query["date"] = {"$lt": datetime.utcnow()}
        sort_direction = -1  # Descending for past

    # Get classes
    classes = list(db.classes.find(query).sort("date", sort_direction).limit(10))

    # Add course info to each class
    for class_item in classes:
        course = db.courses.find_one({"_id": class_item["course_id"]})
        if course:
            class_item["course"] = {
                "id": str(course["_id"]),
                "name": course["name"],
                "level": course["level"]
            }

    return parse_json(classes)


@app.get("/dashboard/resources", response_model=List[Dict[str, Any]])
async def get_learning_resources(
        current_user: User = Depends(get_current_active_user),
        category: Optional[str] = None
):
    # Get user's courses
    user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
    course_ids = [uc["course_id"] for uc in user_courses]

    # Get course levels
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))
    levels = [course["level"] for course in courses]

    # Build query
    query = {"level": {"$in": levels}}
    if category:
        query["category"] = category

    # Get resources
    resources = list(db.resources.find(query))

    return parse_json(resources)


@app.get("/dashboard/profile", response_model=User)
async def get_user_profile(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.put("/dashboard/profile", response_model=User)
async def update_user_profile(
        profile_update: dict,
        current_user: User = Depends(get_current_active_user)
):
    # Update user profile
    update_data = {k: v for k, v in profile_update.items() if k not in ["id", "email", "role", "hashed_password"]}
    update_data["updated_at"] = datetime.utcnow()

    db.users.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": update_data}
    )

    # Return updated user
    updated_user = db.users.find_one({"_id": ObjectId(current_user.id)})
    return parse_json(updated_user)


# Image upload endpoint
@app.post("/upload/image")
async def upload_image(file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    try:
        # Read file content
        contents = await file.read()

        # Upload to Cloudinary
        result = cloudinary.uploader.upload(contents)
        return {"url": result["secure_url"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to AOCA Resources API"}


# ADMIN ROUTES

# User Management
@app.get("/admin/users", response_model=Dict[str, Any])
async def get_all_users(
        admin_user: User = Depends(get_admin_user),
        skip: int = 0,
        limit: int = 100,
        role: Optional[str] = None,
        search: Optional[str] = None
):
    # Build query
    query = {}
    if role:
        query["role"] = role
    if search:
        query["$or"] = [
            {"first_name": {"$regex": search, "$options": "i"}},
            {"last_name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}}
        ]

    # Get users
    users = list(db.users.find(query).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.users.count_documents(query)

    return {
        "users": parse_json(users),
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.get("/admin/users/{user_id}", response_model=Dict[str, Any])
async def get_user_by_id(
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get user's courses
    user_courses = list(db.user_courses.find({"user_id": ObjectId(user_id)}))
    course_ids = [uc["course_id"] for uc in user_courses]
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))

    user["courses"] = parse_json(courses)

    return parse_json(user)


@app.post("/admin/users", response_model=UserResponse)
async def create_user(
        user: UserCreate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if user already exists
    existing_user = db.users.find_one({"email": user.email})
    if existing_user:
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

    # Insert into database
    result = db.users.insert_one(user_data)

    # Return user data
    created_user = db.users.find_one({"_id": result.inserted_id})
    return parse_json(created_user)


@app.put("/admin/users/{user_id}", response_model=UserResponse)
async def update_user(
        user_id: str,
        user_update: UserUpdate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if user exists
    existing_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update user
    update_data = user_update.dict(exclude_unset=True)

    # Handle password update if provided
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))

    update_data["updated_at"] = datetime.utcnow()

    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )

    # Return updated user
    updated_user = db.users.find_one({"_id": ObjectId(user_id)})
    return parse_json(updated_user)


@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if user exists
    existing_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deleting yourself
    if str(existing_user["_id"]) == str(admin_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # Delete user
    db.users.delete_one({"_id": ObjectId(user_id)})

    # Clean up related data
    db.user_courses.delete_many({"user_id": ObjectId(user_id)})
    db.progress.delete_many({"user_id": ObjectId(user_id)})

    return None


# Course Management
@app.get("/admin/courses", response_model=Dict[str, Any])
async def get_all_courses(
        admin_user: User = Depends(get_admin_user),
        skip: int = 0,
        limit: int = 100,
        level: Optional[str] = None,
        search: Optional[str] = None
):
    # Build query
    query = {}
    if level:
        query["level"] = level
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]

    # Get courses
    courses = list(db.courses.find(query).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.courses.count_documents(query)

    # Add instructor details and enrollment count to each course
    for course in courses:
        # Get instructor details
        if "instructor_id" in course and course["instructor_id"]:
            instructor = db.users.find_one({"_id": course["instructor_id"]})
            if instructor:
                course["instructor"] = {
                    "id": str(instructor["_id"]),
                    "name": f"{instructor.get('first_name', '')} {instructor.get('last_name', '')}",
                    "email": instructor.get("email", "")
                }

        # Get enrollment count
        enrollment_count = db.user_courses.count_documents({"course_id": course["_id"]})
        course["enrollment_count"] = enrollment_count

    return {
        "courses": parse_json(courses),
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.get("/admin/courses/{course_id}", response_model=Dict[str, Any])
async def get_course_by_id(
        course_id: str,
        admin_user: User = Depends(get_admin_user)
):
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Get instructor details
    if "instructor_id" in course and course["instructor_id"]:
        instructor = db.users.find_one({"_id": course["instructor_id"]})
        if instructor:
            course["instructor"] = {
                "id": str(instructor["_id"]),
                "name": f"{instructor.get('first_name', '')} {instructor.get('last_name', '')}",
                "email": instructor.get("email", "")
            }

    # Get enrolled students
    enrollments = list(db.user_courses.find({"course_id": ObjectId(course_id)}))
    student_ids = [enrollment["user_id"] for enrollment in enrollments]
    students = list(db.users.find({"_id": {"$in": student_ids}}))

    # Format student data
    formatted_students = []
    for student in students:
        formatted_students.append({
            "id": str(student["_id"]),
            "name": f"{student.get('first_name', '')} {student.get('last_name', '')}",
            "email": student.get("email", ""),
            "enrollment_date": next((e["enrolled_at"] for e in enrollments if e["user_id"] == student["_id"]), None)
        })

    course["students"] = formatted_students

    # Get classes for this course
    classes = list(db.classes.find({"course_id": ObjectId(course_id)}).sort("date", 1))
    course["classes"] = parse_json(classes)

    # Get assignments for this course
    assignments = list(db.assignments.find({"course_id": ObjectId(course_id)}).sort("due_date", 1))
    course["assignments"] = parse_json(assignments)

    return parse_json(course)


@app.post("/admin/courses", response_model=CourseResponse)
async def create_course(
        course: CourseCreate,
        admin_user: User = Depends(get_admin_user)
):
    # Prepare course data
    course_data = course.dict()
    course_data["created_at"] = datetime.utcnow()
    course_data["updated_at"] = datetime.utcnow()

    # Convert instructor_id to ObjectId if provided
    if "instructor_id" in course_data and course_data["instructor_id"]:
        # Verify instructor exists
        instructor = db.users.find_one({"_id": ObjectId(course_data["instructor_id"])})
        if not instructor:
            raise HTTPException(status_code=404, detail="Instructor not found")
        course_data["instructor_id"] = ObjectId(course_data["instructor_id"])

    # Insert into database
    result = db.courses.insert_one(course_data)

    # Return created course
    created_course = db.courses.find_one({"_id": result.inserted_id})
    return parse_json(created_course)


@app.put("/admin/courses/{course_id}", response_model=CourseResponse)
async def update_course(
        course_id: str,
        course_update: CourseUpdate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if course exists
    existing_course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not existing_course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Update course
    update_data = course_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    # Convert instructor_id to ObjectId if provided
    if "instructor_id" in update_data and update_data["instructor_id"]:
        # Verify instructor exists
        instructor = db.users.find_one({"_id": ObjectId(update_data["instructor_id"])})
        if not instructor:
            raise HTTPException(status_code=404, detail="Instructor not found")
        update_data["instructor_id"] = ObjectId(update_data["instructor_id"])

    db.courses.update_one(
        {"_id": ObjectId(course_id)},
        {"$set": update_data}
    )

    # Return updated course
    updated_course = db.courses.find_one({"_id": ObjectId(course_id)})
    return parse_json(updated_course)


@app.delete("/admin/courses/{course_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_course(
        course_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if course exists
    existing_course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not existing_course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Delete course
    db.courses.delete_one({"_id": ObjectId(course_id)})

    # Clean up related data
    db.user_courses.delete_many({"course_id": ObjectId(course_id)})
    db.classes.delete_many({"course_id": ObjectId(course_id)})
    db.assignments.delete_many({"course_id": ObjectId(course_id)})
    db.progress.delete_many({"course_id": ObjectId(course_id)})

    return None


@app.post("/admin/courses/{course_id}/enroll/{user_id}", status_code=status.HTTP_200_OK)
async def enroll_user_in_course(
        course_id: str,
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if course exists
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Check if user exists
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already enrolled
    existing_enrollment = db.user_courses.find_one({
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id)
    })

    if existing_enrollment:
        return {"message": "User already enrolled in this course"}

    # Create enrollment
    enrollment_data = {
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id),
        "enrolled_at": datetime.utcnow(),
        "status": "active"
    }

    db.user_courses.insert_one(enrollment_data)

    # Initialize progress record
    progress_data = {
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id),
        "percentage": 0,
        "modules_completed": [],
        "last_activity": datetime.utcnow()
    }

    db.progress.insert_one(progress_data)

    return {"message": "User successfully enrolled in course"}


@app.delete("/admin/courses/{course_id}/enroll/{user_id}", status_code=status.HTTP_200_OK)
async def remove_user_from_course(
        course_id: str,
        user_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if enrollment exists
    enrollment = db.user_courses.find_one({
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id)
    })

    if not enrollment:
        raise HTTPException(status_code=404, detail="Enrollment not found")

    # Remove enrollment
    db.user_courses.delete_one({
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id)
    })

    # Remove progress data
    db.progress.delete_one({
        "user_id": ObjectId(user_id),
        "course_id": ObjectId(course_id)
    })

    return {"message": "User successfully removed from course"}


# Blog Management
@app.get("/admin/blog/categories", response_model=List[Dict[str, Any]])
async def get_blog_categories(
        admin_user: User = Depends(get_admin_user)
):
    # Get all unique categories with post count
    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]

    categories = list(db.blog_posts.aggregate(pipeline))

    formatted_categories = []
    for category in categories:
        formatted_categories.append({
            "name": category["_id"],
            "count": category["count"]
        })

    return formatted_categories


@app.post("/admin/blog/categories", status_code=status.HTTP_201_CREATED)
async def create_blog_category(
        category_data: dict,
        admin_user: User = Depends(get_admin_user)
):
    # This endpoint doesn't actually create a category document
    # since categories are just fields in blog posts
    # It's more of a validation endpoint to ensure consistent category naming

    category_name = category_data.get("name")
    if not category_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Category name is required"
        )

    # Check if category already exists
    existing_post = db.blog_posts.find_one({"category": category_name})
    if existing_post:
        return {"message": "Category already exists", "name": category_name}

    # Create a dummy post with this category to make it available
    # This is optional and can be removed if not needed
    dummy_post = {
        "title": f"Category: {category_name}",
        "slug": f"category-{category_name.lower().replace(' ', '-')}",
        "excerpt": f"This is a placeholder post for the {category_name} category.",
        "content": f"<p>This is a placeholder post for the {category_name} category.</p>",
        "category": category_name,
        "tags": [category_name.lower()],
        "author_id": ObjectId(admin_user.id),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "is_published": False,  # Mark as unpublished
        "is_placeholder": True  # Mark as placeholder
    }

    db.blog_posts.insert_one(dummy_post)

    return {"message": "Category created successfully", "name": category_name}


@app.put("/admin/blog/categories/{old_name}", status_code=status.HTTP_200_OK)
async def update_blog_category(
        old_name: str,
        category_data: dict,
        admin_user: User = Depends(get_admin_user)
):
    new_name = category_data.get("name")
    if not new_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New category name is required"
        )

    # Update all posts with this category
    result = db.blog_posts.update_many(
        {"category": old_name},
        {"$set": {"category": new_name}}
    )

    return {
        "message": "Category updated successfully",
        "old_name": old_name,
        "new_name": new_name,
        "posts_updated": result.modified_count
    }


@app.delete("/admin/blog/categories/{name}", status_code=status.HTTP_200_OK)
async def delete_blog_category(
        name: str,
        admin_user: User = Depends(get_admin_user)
):
    # Count posts with this category
    post_count = db.blog_posts.count_documents({"category": name})

    if post_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete category with {post_count} posts. Update or delete the posts first."
        )

    # Delete any placeholder posts for this category
    result = db.blog_posts.delete_many({
        "category": name,
        "is_placeholder": True
    })

    return {
        "message": "Category deleted successfully",
        "name": name,
        "placeholder_posts_deleted": result.deleted_count
    }


# Class Management
@app.get("/admin/classes", response_model=Dict[str, Any])
async def get_all_classes(
        admin_user: User = Depends(get_admin_user),
        skip: int = 0,
        limit: int = 100,
        course_id: Optional[str] = None,
        upcoming: Optional[bool] = None
):
    # Build query
    query = {}
    if course_id:
        query["course_id"] = ObjectId(course_id)
    if upcoming is not None:
        if upcoming:
            query["date"] = {"$gte": datetime.utcnow()}
        else:
            query["date"] = {"$lt": datetime.utcnow()}

    # Get classes
    classes = list(db.classes.find(query).sort("date", 1).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.classes.count_documents(query)

    # Add course and instructor info to each class
    for class_item in classes:
        # Get course info
        course = db.courses.find_one({"_id": class_item["course_id"]})
        if course:
            class_item["course"] = {
                "id": str(course["_id"]),
                "name": course["name"],
                "level": course["level"]
            }

        # Get instructor info
        if "instructor_id" in class_item and class_item["instructor_id"]:
            instructor = db.users.find_one({"_id": class_item["instructor_id"]})
            if instructor:
                class_item["instructor"] = {
                    "id": str(instructor["_id"]),
                    "name": f"{instructor.get('first_name', '')} {instructor.get('last_name', '')}",
                    "email": instructor.get("email", "")
                }

    return {
        "classes": parse_json(classes),
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.post("/admin/classes", response_model=ClassResponse)
async def create_class(
        class_data: ClassCreate,
        admin_user: User = Depends(get_admin_user)
):
    # Prepare class data
    class_dict = class_data.dict()

    # Verify course exists
    course = db.courses.find_one({"_id": ObjectId(class_dict["course_id"])})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    class_dict["course_id"] = ObjectId(class_dict["course_id"])

    # Verify instructor exists if provided
    if "instructor_id" in class_dict and class_dict["instructor_id"]:
        instructor = db.users.find_one({"_id": ObjectId(class_dict["instructor_id"])})
        if not instructor:
            raise HTTPException(status_code=404, detail="Instructor not found")
        class_dict["instructor_id"] = ObjectId(class_dict["instructor_id"])

    class_dict["created_at"] = datetime.utcnow()
    class_dict["updated_at"] = datetime.utcnow()

    # Insert into database
    result = db.classes.insert_one(class_dict)

    # Return created class
    created_class = db.classes.find_one({"_id": result.inserted_id})
    return parse_json(created_class)


@app.put("/admin/classes/{class_id}", response_model=ClassResponse)
async def update_class(
        class_id: str,
        class_update: ClassUpdate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if class exists
    existing_class = db.classes.find_one({"_id": ObjectId(class_id)})
    if not existing_class:
        raise HTTPException(status_code=404, detail="Class not found")

    # Update class
    update_data = class_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    # Convert IDs to ObjectId
    if "course_id" in update_data:
        # Verify course exists
        course = db.courses.find_one({"_id": ObjectId(update_data["course_id"])})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        update_data["course_id"] = ObjectId(update_data["course_id"])

    if "instructor_id" in update_data and update_data["instructor_id"]:
        # Verify instructor exists
        instructor = db.users.find_one({"_id": ObjectId(update_data["instructor_id"])})
        if not instructor:
            raise HTTPException(status_code=404, detail="Instructor not found")
        update_data["instructor_id"] = ObjectId(update_data["instructor_id"])

    db.classes.update_one(
        {"_id": ObjectId(class_id)},
        {"$set": update_data}
    )

    # Return updated class
    updated_class = db.classes.find_one({"_id": ObjectId(class_id)})
    return parse_json(updated_class)


@app.delete("/admin/classes/{class_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_class(
        class_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if class exists
    existing_class = db.classes.find_one({"_id": ObjectId(class_id)})
    if not existing_class:
        raise HTTPException(status_code=404, detail="Class not found")

    # Delete class
    db.classes.delete_one({"_id": ObjectId(class_id)})

    return None


# Assignment Management
@app.get("/admin/assignments", response_model=Dict[str, Any])
async def get_all_assignments(
        admin_user: User = Depends(get_admin_user),
        skip: int = 0,
        limit: int = 100,
        course_id: Optional[str] = None,
        status: Optional[str] = None
):
    # Build query
    query = {}
    if course_id:
        query["course_id"] = ObjectId(course_id)

    if status == "pending":
        query["due_date"] = {"$gte": datetime.utcnow()}
    elif status == "overdue":
        query["due_date"] = {"$lt": datetime.utcnow()}

    # Get assignments
    assignments = list(db.assignments.find(query).sort("due_date", 1).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.assignments.count_documents(query)

    # Add course info to each assignment
    for assignment in assignments:
        course = db.courses.find_one({"_id": assignment["course_id"]})
        if course:
            assignment["course"] = {
                "id": str(course["_id"]),
                "name": course["name"],
                "level": course["level"]
            }

        # Count submissions
        assignment["submission_count"] = len(assignment.get("submissions", []))

    return {
        "assignments": parse_json(assignments),
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.post("/admin/assignments", response_model=AssignmentResponse)
async def create_assignment(
        assignment_data: AssignmentCreate,
        admin_user: User = Depends(get_admin_user)
):
    # Prepare assignment data
    assignment_dict = assignment_data.dict()

    # Verify course exists
    course = db.courses.find_one({"_id": ObjectId(assignment_dict["course_id"])})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    assignment_dict["course_id"] = ObjectId(assignment_dict["course_id"])
    assignment_dict["created_at"] = datetime.utcnow()
    assignment_dict["updated_at"] = datetime.utcnow()
    assignment_dict["submissions"] = []

    # Insert into database
    result = db.assignments.insert_one(assignment_dict)

    # Return created assignment
    created_assignment = db.assignments.find_one({"_id": result.inserted_id})
    return parse_json(created_assignment)


@app.put("/admin/assignments/{assignment_id}", response_model=AssignmentResponse)
async def update_assignment(
        assignment_id: str,
        assignment_update: AssignmentUpdate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if assignment exists
    existing_assignment = db.assignments.find_one({"_id": ObjectId(assignment_id)})
    if not existing_assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Update assignment
    update_data = assignment_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    # Convert course_id to ObjectId if provided
    if "course_id" in update_data:
        # Verify course exists
        course = db.courses.find_one({"_id": ObjectId(update_data["course_id"])})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        update_data["course_id"] = ObjectId(update_data["course_id"])

    db.assignments.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": update_data}
    )

    # Return updated assignment
    updated_assignment = db.assignments.find_one({"_id": ObjectId(assignment_id)})
    return parse_json(updated_assignment)


@app.delete("/admin/assignments/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assignment(
        assignment_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if assignment exists
    existing_assignment = db.assignments.find_one({"_id": ObjectId(assignment_id)})
    if not existing_assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Delete assignment
    db.assignments.delete_one({"_id": ObjectId(assignment_id)})

    return None


@app.get("/admin/assignments/{assignment_id}/submissions", response_model=List[Dict[str, Any]])
async def get_assignment_submissions(
        assignment_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if assignment exists
    assignment = db.assignments.find_one({"_id": ObjectId(assignment_id)})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Get submissions
    submissions = assignment.get("submissions", [])

    # Add user info to each submission
    for submission in submissions:
        if "user_id" in submission:
            user = db.users.find_one({"_id": submission["user_id"]})
            if user:
                submission["user"] = {
                    "id": str(user["_id"]),
                    "name": f"{user.get('first_name', '')} {user.get('last_name', '')}",
                    "email": user.get("email", "")
                }

    return parse_json(submissions)


@app.post("/admin/assignments/{assignment_id}/grade/{user_id}", status_code=status.HTTP_200_OK)
async def grade_assignment_submission(
        assignment_id: str,
        user_id: str,
        grade_data: dict,
        admin_user: User = Depends(get_admin_user)
):
    # Check if assignment exists
    assignment = db.assignments.find_one({"_id": ObjectId(assignment_id)})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Check if user exists
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if submission exists
    submissions = assignment.get("submissions", [])
    submission_index = None

    for i, submission in enumerate(submissions):
        if str(submission.get("user_id")) == user_id:
            submission_index = i
            break

    if submission_index is None:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Update submission with grade and feedback
    score = grade_data.get("score")
    feedback = grade_data.get("feedback")

    if score is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Score is required"
        )

    # Update the submission
    submissions[submission_index]["score"] = score
    submissions[submission_index]["feedback"] = feedback
    submissions[submission_index]["graded_at"] = datetime.utcnow()
    submissions[submission_index]["graded_by"] = ObjectId(admin_user.id)

    # Update assignment with modified submissions
    db.assignments.update_one(
        {"_id": ObjectId(assignment_id)},
        {"$set": {"submissions": submissions}}
    )

    return {"message": "Submission graded successfully"}


# Resource Management
@app.get("/admin/resources", response_model=Dict[str, Any])
async def get_all_resources(
        admin_user: User = Depends(get_admin_user),
        skip: int = 0,
        limit: int = 100,
        level: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None
):
    # Build query
    query = {}
    if level:
        query["level"] = level
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]

    # Get resources
    resources = list(db.resources.find(query).skip(skip).limit(limit))

    # Get total count for pagination
    total = db.resources.count_documents(query)

    return {
        "resources": parse_json(resources),
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.post("/admin/resources", response_model=ResourceResponse)
async def create_resource(
        resource_data: ResourceCreate,
        admin_user: User = Depends(get_admin_user)
):
    # Prepare resource data
    resource_dict = resource_data.dict()
    resource_dict["created_at"] = datetime.utcnow()
    resource_dict["updated_at"] = datetime.utcnow()
    resource_dict["created_by"] = ObjectId(admin_user.id)

    # Insert into database
    result = db.resources.insert_one(resource_dict)

    # Return created resource
    created_resource = db.resources.find_one({"_id": result.inserted_id})
    return parse_json(created_resource)


@app.put("/admin/resources/{resource_id}", response_model=ResourceResponse)
async def update_resource(
        resource_id: str,
        resource_update: ResourceUpdate,
        admin_user: User = Depends(get_admin_user)
):
    # Check if resource exists
    existing_resource = db.resources.find_one({"_id": ObjectId(resource_id)})
    if not existing_resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Update resource
    update_data = resource_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    db.resources.update_one(
        {"_id": ObjectId(resource_id)},
        {"$set": update_data}
    )

    # Return updated resource
    updated_resource = db.resources.find_one({"_id": ObjectId(resource_id)})
    return parse_json(updated_resource)


@app.delete("/admin/resources/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_resource(
        resource_id: str,
        admin_user: User = Depends(get_admin_user)
):
    # Check if resource exists
    existing_resource = db.resources.find_one({"_id": ObjectId(resource_id)})
    if not existing_resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Delete resource
    db.resources.delete_one({"_id": ObjectId(resource_id)})

    return None


# Dashboard Statistics
@app.get("/admin/dashboard/stats", response_model=Dict[str, Any])
async def get_admin_dashboard_stats(
        admin_user: User = Depends(get_admin_user)
):
    # Get user statistics
    total_users = db.users.count_documents({})
    active_users = db.users.count_documents({"disabled": False})
    user_roles = list(db.users.aggregate([
        {"$group": {"_id": "$role", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))

    # Get course statistics
    total_courses = db.courses.count_documents({})
    total_enrollments = db.user_courses.count_documents({})
    courses_by_level = list(db.courses.aggregate([
        {"$group": {"_id": "$level", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))

    # Get blog statistics
    total_posts = db.blog_posts.count_documents({})
    posts_by_category = list(db.blog_posts.aggregate([
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]))
    total_comments = db.comments.count_documents({})

    # Get recent activity
    recent_users = list(db.users.find().sort("created_at", -1).limit(5))
    recent_enrollments = list(db.user_courses.find().sort("enrolled_at", -1).limit(5))
    recent_posts = list(db.blog_posts.find().sort("created_at", -1).limit(5))

    # Add user info to recent enrollments
    for enrollment in recent_enrollments:
        user = db.users.find_one({"_id": enrollment["user_id"]})
        course = db.courses.find_one({"_id": enrollment["course_id"]})

        if user:
            enrollment["user"] = {
                "id": str(user["_id"]),
                "name": f"{user.get('first_name', '')} {user.get('last_name', '')}",
                "email": user.get("email", "")
            }

        if course:
            enrollment["course"] = {
                "id": str(course["_id"]),
                "name": course["name"],
                "level": course["level"]
            }

    return {
        "user_stats": {
            "total": total_users,
            "active": active_users,
            "by_role": parse_json(user_roles)
        },
        "course_stats": {
            "total": total_courses,
            "enrollments": total_enrollments,
            "by_level": parse_json(courses_by_level)
        },
        "blog_stats": {
            "total_posts": total_posts,
            "by_category": parse_json(posts_by_category),
            "total_comments": total_comments
        },
        "recent_activity": {
            "users": parse_json(recent_users),
            "enrollments": parse_json(recent_enrollments),
            "posts": parse_json(recent_posts)
        }
    }


