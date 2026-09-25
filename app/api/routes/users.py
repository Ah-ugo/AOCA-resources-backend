from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from typing import Dict, Any, Optional, List
from datetime import datetime
from bson import ObjectId
import uuid

from .common import (
    User, UserUpdate, UserResponse,
    ContactForm, AdmissionInquiry,
    get_current_active_user, get_password_hash,
    parse_json, db,
)
import cloudinary.uploader

router = APIRouter()


@router.get("/profile", response_model=Dict[str, Any])
async def get_profile(current_user: User = Depends(get_current_active_user)):
    """Get current user profile with enrolled courses."""
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
    course_ids = [uc["course_id"] for uc in user_courses]
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))
    user["courses"] = parse_json(courses)
    return parse_json(user)


@router.put("/profile", response_model=User)
async def update_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
):
    """Update current user profile."""
    try:
        update_data = user_update.dict(exclude_unset=True)
        if "password" in update_data:
            update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
        # Prevent privilege escalation
        update_data.pop("role", None)
        update_data.pop("disabled", None)
        update_data["updated_at"] = datetime.utcnow()
        db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": update_data})
        updated_user = db.users.find_one({"_id": ObjectId(current_user.id)})
        return parse_json(updated_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/upload-image")
async def upload_profile_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a profile image."""
    try:
        allowed_extensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"]
        file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type not allowed. Allowed: {', '.join(allowed_extensions)}",
            )
        contents = await file.read()
        if len(contents) > 5 * 1024 * 1024:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File too large. Maximum size is 5MB")
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        public_id = f"profile_{current_user.id}_{timestamp}_{unique_id}"
        result = cloudinary.uploader.upload(contents, folder="profile_images", public_id=public_id)
        image_url = result["secure_url"]
        db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"image": image_url, "updated_at": datetime.utcnow()}},
        )
        return {"url": image_url, "message": "Profile image uploaded successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading image: {str(e)}")


@router.get("/instructors", response_model=List[Dict[str, Any]])
async def get_instructors():
    """Get all instructors (public endpoint)."""
    try:
        instructors = list(db.users.find({"role": "instructor", "disabled": False}))
        for instructor in instructors:
            course_ids = list(db.courses.distinct("_id", {"instructor_id": instructor["_id"]}))
            instructor["total_students"] = db.user_courses.count_documents({
                "course_id": {"$in": course_ids}, "status": "active"
            })
            instructor["total_courses"] = len(course_ids)
            instructor.pop("hashed_password", None)
        return parse_json(instructors)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/contact", response_model=Dict[str, Any])
async def submit_contact_form(form: ContactForm):
    """Public contact form submission."""
    try:
        form_data = form.dict()
        form_data["created_at"] = datetime.utcnow()
        form_data["is_read"] = False
        form_data["status"] = "pending"
        result = db.contact_submissions.insert_one(form_data)
        return {
            "success": True,
            "message": "Your message has been received. We will get back to you shortly.",
            "id": str(result.inserted_id),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/admission-inquiry", response_model=Dict[str, Any])
async def submit_admission_inquiry(inquiry: AdmissionInquiry):
    """Public admission inquiry submission."""
    try:
        inquiry_data = inquiry.dict()
        inquiry_data["created_at"] = datetime.utcnow()
        inquiry_data["updated_at"] = datetime.utcnow()
        inquiry_data["is_read"] = False
        inquiry_data["status"] = "pending"
        inquiry_data["admin_notes"] = []
        result = db.admission_inquiries.insert_one(inquiry_data)
        return {
            "success": True,
            "message": "Your admission inquiry has been received. We will get back to you shortly.",
            "id": str(result.inserted_id),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
