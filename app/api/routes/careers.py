from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from typing import Dict, Any, Optional, List
from datetime import datetime
from bson import ObjectId
import uuid
import os

from .common import (
    JobListingCreate, JobListingUpdate, JobListingResponse,
    JobApplicationCreate, JobApplicationResponse,
    JobCategory, JobCategoryCreate, JobCategoryUpdate,
    User, get_current_active_user,
    parse_json, db,
)

router = APIRouter()


@router.get("/jobs", response_model=Dict[str, Any])
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
    sort_order: int = -1,
):
    """Get all published job listings with filters."""
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
            ]

        jobs = list(
            db.job_listings.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
        )
        total = db.job_listings.count_documents(query)

        for job in jobs:
            db.job_listings.update_one({"_id": job["_id"]}, {"$inc": {"views": 1}})

        categories = list(db.job_categories.find())
        locations = list(
            db.job_listings.aggregate([
                {"$match": {"is_published": True}},
                {"$group": {"_id": "$location.city", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ])
        )
        employment_types = list(
            db.job_listings.aggregate([
                {"$match": {"is_published": True}},
                {"$group": {"_id": "$employment_type", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ])
        )
        experience_levels = list(
            db.job_listings.aggregate([
                {"$match": {"is_published": True}},
                {"$group": {"_id": "$experience_level", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ])
        )

        return {
            "jobs": parse_json(jobs),
            "total": total,
            "skip": skip,
            "limit": limit,
            "filters": {
                "categories": parse_json(categories),
                "locations": parse_json(locations),
                "employment_types": parse_json(employment_types),
                "experience_levels": parse_json(experience_levels),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs/{job_id}", response_model=Dict[str, Any])
async def get_job_listing(job_id: str):
    """Get a single job listing by ID."""
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        job = db.job_listings.find_one({"_id": ObjectId(job_id), "is_published": True})
        if not job:
            raise HTTPException(status_code=404, detail="Job listing not found")

        db.job_listings.update_one({"_id": ObjectId(job_id)}, {"$inc": {"views": 1}})

        if job.get("created_by"):
            creator = db.users.find_one({"_id": job["created_by"]})
            if creator:
                job["created_by_user"] = {
                    "id": str(creator["_id"]),
                    "name": f"{creator.get('first_name', '')} {creator.get('last_name', '')}",
                    "email": creator.get("email", ""),
                }

        similar_jobs = list(
            db.job_listings.find(
                {"category": job["category"], "_id": {"$ne": ObjectId(job_id)}, "is_published": True}
            ).sort("created_at", -1).limit(3)
        )
        job["similar_jobs"] = parse_json(similar_jobs)
        return parse_json(job)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories", response_model=List[Dict[str, Any]])
async def get_job_categories():
    """Get all job categories with job counts."""
    try:
        categories = list(db.job_categories.find().sort("name", 1))
        for category in categories:
            category["job_count"] = db.job_listings.count_documents(
                {"category": category["name"], "is_published": True}
            )
        return parse_json(categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/jobs/{job_id}/apply", response_model=JobApplicationResponse)
async def apply_for_job(job_id: str, application: JobApplicationCreate):
    """Apply for a job (public endpoint)."""
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")

        job = db.job_listings.find_one({"_id": ObjectId(job_id), "is_published": True})
        if not job:
            raise HTTPException(status_code=404, detail="Job listing not found")

        if job.get("application_deadline") and datetime.utcnow() > job["application_deadline"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Application deadline has passed",
            )

        existing = db.job_applications.find_one(
            {"email": application.email, "job_id": ObjectId(job_id)}
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You have already applied for this job",
            )

        application_data = application.dict()
        application_data["job_id"] = ObjectId(job_id)
        application_data["created_at"] = datetime.utcnow()
        application_data["updated_at"] = datetime.utcnow()
        application_data["status"] = "applied"

        result = db.job_applications.insert_one(application_data)
        db.job_listings.update_one(
            {"_id": ObjectId(job_id)}, {"$inc": {"applications_count": 1}}
        )

        created_application = db.job_applications.find_one({"_id": result.inserted_id})
        created_application["job"] = {
            "id": str(job["_id"]),
            "title": job["title"],
            "company": job["company"],
        }
        return parse_json(created_application)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/upload/resume")
async def upload_resume(file: UploadFile = File(...)):
    """Upload a resume file (public endpoint)."""
    try:
        allowed_extensions = [".pdf", ".doc", ".docx"]
        file_ext = os.path.splitext(file.filename)[1].lower()

        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}",
            )

        contents = await file.read()
        if len(contents) > 5 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 5MB",
            )

        import cloudinary.uploader
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        public_id = f"resume_{timestamp}_{unique_id}"

        try:
            result = cloudinary.uploader.upload(
                contents, resource_type="raw", folder="resumes", public_id=public_id
            )
        except Exception:
            result = cloudinary.uploader.upload(
                contents, folder="resumes", public_id=public_id
            )

        return {"url": result["secure_url"]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")
