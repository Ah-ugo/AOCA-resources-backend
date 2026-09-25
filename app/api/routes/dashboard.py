from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Dict, Any, Optional, List
from datetime import datetime
from bson import ObjectId
import uuid

from .common import (
    User, get_current_active_user, parse_json, db,
)

router = APIRouter()


@router.get("", response_model=Dict[str, Any])
async def get_user_dashboard(current_user: User = Depends(get_current_active_user)):
    """Master student dashboard — one call for everything."""
    user_oid = ObjectId(current_user.id)

    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids = [e["course_id"] for e in enrollments]
    courses_raw = list(db.courses.find({"_id": {"$in": course_ids}}))

    courses = []
    for c in courses_raw:
        prog = db.progress.find_one({"user_id": user_oid, "course_id": c["_id"]})
        c.setdefault("title", c.get("name", ""))
        c.setdefault("name", c.get("title", ""))
        courses.append({
            **parse_json(c),
            "progress": prog.get("percentage", 0) if prog else 0,
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
                cls["instructor"] = {
                    "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip()
                }

    pending_assignments = list(
        db.assignments.find({"course_id": {"$in": course_ids}}).sort("due_date", 1).limit(10)
    )

    levels = list({c.get("level") for c in courses_raw if c.get("level")})
    resources = list(db.resources.find({"level": {"$in": levels}}).limit(6)) if levels else []

    return {
        "courses": courses,
        "upcoming_classes": parse_json(upcoming_classes),
        "pending_assignments": parse_json(pending_assignments),
        "resources": parse_json(resources),
    }


@router.get("/overview", response_model=Dict[str, Any])
async def get_dashboard_overview(current_user: User = Depends(get_current_active_user)):
    """Get dashboard overview for current user."""
    try:
        user_courses = list(db.user_courses.find({"user_id": ObjectId(current_user.id)}))
        course_ids = [uc["course_id"] for uc in user_courses]
        courses = list(db.courses.find({"_id": {"$in": course_ids}}))

        upcoming_classes = list(
            db.classes.find({"course_id": {"$in": course_ids}, "date": {"$gte": datetime.utcnow()}})
            .sort("date", 1).limit(3)
        )
        pending_assignments = list(
            db.assignments.find({
                "course_id": {"$in": course_ids},
                "due_date": {"$gte": datetime.utcnow()},
                "submissions.user_id": {"$ne": ObjectId(current_user.id)},
            }).sort("due_date", 1).limit(5)
        )

        for course in courses:
            progress = db.progress.find_one({
                "user_id": ObjectId(current_user.id),
                "course_id": course["_id"],
            })
            course["progress"] = progress["percentage"] if progress else 0

        return {
            "courses": parse_json(courses),
            "upcoming_classes": parse_json(upcoming_classes),
            "pending_assignments": parse_json(pending_assignments),
            "user": parse_json(current_user.dict()),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/courses", response_model=List[Dict[str, Any]])
async def get_user_courses_dashboard(current_user: User = Depends(get_current_active_user)):
    """Get enrolled courses for the current student."""
    user_oid = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids = [e["course_id"] for e in enrollments]
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))

    result = []
    for c in courses:
        prog = db.progress.find_one({"user_id": user_oid, "course_id": c["_id"]})
        c.setdefault("title", c.get("name", ""))
        c.setdefault("name", c.get("title", ""))
        c["progress"] = prog.get("percentage", 0) if prog else 0
        result.append(parse_json(c))
    return result


@router.get("/courses/{course_id}", response_model=Dict[str, Any])
async def get_course_for_student(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Student course detail — used by VideoPlayer.jsx."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")

    enrollment = db.user_courses.find_one({
        "user_id": ObjectId(str(current_user.id)),
        "course_id": ObjectId(course_id),
        "status": "active",
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")

    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    course.setdefault("title", course.get("name", ""))
    course.setdefault("name", course.get("title", ""))

    if course.get("instructor_id"):
        inst = db.users.find_one({"_id": course["instructor_id"]})
        if inst:
            course["instructor"] = {
                "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email"),
            }

    modules_from_collection = list(
        db.modules.find({"course_id": ObjectId(course_id)}).sort("order", 1)
    )
    course["modules"] = modules_from_collection or course.get("modules", [])
    return parse_json(course)


@router.get("/courses/{course_id}/resume", response_model=Dict[str, Any])
async def get_resume_state(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Returns the lesson the student should resume."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")

    progress = db.progress.find_one({
        "user_id": ObjectId(str(current_user.id)),
        "course_id": ObjectId(course_id),
    })
    last_id = progress.get("last_lesson_id") if progress else None
    return {
        "course_id": course_id,
        "last_lesson_id": str(last_id) if last_id else None,
        "percentage": progress.get("percentage", 0) if progress else 0,
    }


@router.get("/assignments", response_model=Dict[str, Any])
async def get_user_assignments_dashboard(
    current_user: User = Depends(get_current_active_user),
    status: Optional[str] = None,
):
    """Get assignments for enrolled courses."""
    user_oid = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids = [e["course_id"] for e in enrollments]

    query: dict = {"course_id": {"$in": course_ids}}
    now = datetime.utcnow()

    if status == "pending":
        query["due_date"] = {"$gte": now}
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
        submitted = any(str(s.get("user_id")) == str(user_oid) for s in a.get("submissions", []))
        if submitted:
            a["status"] = "completed"
        elif a.get("due_date") and a["due_date"] < now:
            a["status"] = "overdue"
        else:
            a["status"] = "pending"

    return {"assignments": parse_json(assignments)}


@router.get("/classes", response_model=Dict[str, Any])
async def get_user_classes_dashboard(
    current_user: User = Depends(get_current_active_user),
    upcoming: bool = True,
):
    """Get classes for enrolled courses."""
    user_oid = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids = [e["course_id"] for e in enrollments]

    now = datetime.utcnow()
    date_filter = {"$gte": now} if upcoming else {"$lt": now}
    sort_dir = 1 if upcoming else -1

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


@router.get("/classes/{class_id}", response_model=Dict[str, Any])
async def get_class_for_student(
    class_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get a single class for a student."""
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
                "_id": str(inst["_id"]),
                "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email"),
            }

    return parse_json(cls)


@router.get("/resources", response_model=Dict[str, Any])
async def get_learning_resources_dashboard(
    current_user: User = Depends(get_current_active_user),
    category: Optional[str] = None,
    search: Optional[str] = None,
):
    """Get resources matched to enrolled course levels."""
    user_oid = ObjectId(current_user.id)
    enrollments = list(db.user_courses.find({"user_id": user_oid, "status": "active"}))
    course_ids = [e["course_id"] for e in enrollments]
    courses = list(db.courses.find({"_id": {"$in": course_ids}}))
    levels = list({c.get("level") for c in courses if c.get("level")})

    query: dict = {}
    if levels:
        query["level"] = {"$in": levels}
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]

    resources = list(db.resources.find(query))
    return {"resources": parse_json(resources)}


@router.get("/resources/categories", response_model=Dict[str, Any])
async def get_resource_categories(current_user: User = Depends(get_current_active_user)):
    """Get all resource categories."""
    cats = db.resources.distinct("category")
    return {"categories": [{"id": c, "name": c} for c in cats if c]}


@router.get("/profile", response_model=Dict[str, Any])
async def get_dashboard_profile(current_user: User = Depends(get_current_active_user)):
    """Get current user profile."""
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": parse_json(user)}


@router.put("/profile", response_model=Dict[str, Any])
async def update_dashboard_profile(
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    """Update current user profile (safe fields only)."""
    ALLOWED = {"first_name", "last_name", "phone", "address", "bio", "image"}
    update_data = {k: v for k, v in body.items() if k in ALLOWED and v is not None}

    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    update_data["updated_at"] = datetime.utcnow()
    db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": update_data})
    updated = db.users.find_one({"_id": ObjectId(current_user.id)})
    return {"user": parse_json(updated)}


@router.get("/progress/{course_id}", response_model=Dict[str, Any])
async def get_course_progress(
    course_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get student progress for a specific course."""
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")

    enrollment = db.user_courses.find_one({
        "user_id": ObjectId(current_user.id),
        "course_id": ObjectId(course_id),
        "status": "active",
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")

    progress = db.progress.find_one({
        "user_id": ObjectId(current_user.id),
        "course_id": ObjectId(course_id),
    })

    completed_ids = [str(lid) for lid in (progress.get("completed_lesson_ids", []) if progress else [])]

    course = db.courses.find_one({"_id": ObjectId(course_id)})
    all_lessons = []
    for mod in (course.get("modules", []) if course else []):
        all_lessons.extend(mod.get("lessons", []))

    total = len(all_lessons)
    done = len(completed_ids)
    pct = round((done / total) * 100) if total else 0

    return {
        "course_id": course_id,
        "completed_lesson_ids": completed_ids,
        "total_lessons": total,
        "completed_count": done,
        "percentage": pct,
        "last_lesson_id": str(progress["last_lesson_id"]) if progress and progress.get("last_lesson_id") else None,
        "last_active": progress["last_active"].isoformat() if progress and progress.get("last_active") else None,
    }


@router.post("/progress/lesson/{lesson_id}/complete", response_model=Dict[str, Any])
async def mark_lesson_complete(
    lesson_id: str,
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    """Mark a lesson complete. Idempotent. Auto-generates certificate at 100%."""
    course_id = body.get("course_id")
    if not course_id or not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="course_id required")
    if not ObjectId.is_valid(lesson_id):
        raise HTTPException(status_code=400, detail="Invalid lesson ID")

    lesson_oid = ObjectId(lesson_id)
    course_oid = ObjectId(course_id)
    user_oid = ObjectId(str(current_user.id))

    enrollment = db.user_courses.find_one({
        "user_id": user_oid, "course_id": course_oid, "status": "active"
    })
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")

    db.progress.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {
            "$addToSet": {"completed_lesson_ids": lesson_oid},
            "$set": {"last_lesson_id": lesson_oid, "last_active": datetime.utcnow()},
        },
        upsert=True,
    )

    progress = db.progress.find_one({"user_id": user_oid, "course_id": course_oid})
    course = db.courses.find_one({"_id": course_oid})
    all_lessons: list = []
    for mod in (course.get("modules", []) if course else []):
        all_lessons.extend(mod.get("lessons", []))

    total = len(all_lessons)
    done = len(progress.get("completed_lesson_ids", []) if progress else [])
    pct = round((done / total) * 100) if total else 0

    db.progress.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$set": {"percentage": pct}},
    )

    certificate_id = None
    if pct == 100:
        existing_cert = db.certificates.find_one({"user_id": user_oid, "course_id": course_oid})
        if not existing_cert:
            cert = {
                "user_id": user_oid,
                "course_id": course_oid,
                "user_name": f"{current_user.first_name} {current_user.last_name}".strip(),
                "course_name": course.get("name", "") if course else "",
                "issued_at": datetime.utcnow(),
                "verification_code": str(uuid.uuid4())[:8].upper(),
            }
            res = db.certificates.insert_one(cert)
            certificate_id = str(res.inserted_id)

    return {
        "lesson_id": lesson_id,
        "percentage": pct,
        "completed": True,
        "course_complete": pct == 100,
        "certificate_id": certificate_id,
    }


@router.get("/certificates", response_model=List[Dict[str, Any]])
async def get_my_certificates(current_user: User = Depends(get_current_active_user)):
    """Get student's earned certificates."""
    certs = list(
        db.certificates.find({"user_id": ObjectId(str(current_user.id))}).sort("issued_at", -1)
    )
    return parse_json(certs)
