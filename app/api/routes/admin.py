from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from bson import ObjectId
import csv
from io import StringIO

from .common import (
    User, UserCreate, UserUpdate, UserResponse,
    JobListingCreate, JobListingUpdate, JobListingResponse,
    JobApplicationUpdate, JobApplicationResponse,
    JobCategory, JobCategoryCreate, JobCategoryUpdate,
    get_admin_user, get_password_hash, parse_json, db,
)

router = APIRouter()


# ==================== USERS ====================

@router.get("/users", response_model=Dict[str, Any])
async def get_all_users(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    role: Optional[str] = None,
    search: Optional[str] = None,
):
    try:
        query = {}
        if role:
            query["role"] = role
        if search:
            query["$or"] = [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
            ]
        users = list(db.users.find(query).skip(skip).limit(limit))
        total = db.users.count_documents(query)
        return {"users": parse_json(users), "total": total, "skip": skip, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/{user_id}", response_model=Dict[str, Any])
async def get_user_by_id(user_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user_courses = list(db.user_courses.find({"user_id": ObjectId(user_id)}))
        course_ids = [uc["course_id"] for uc in user_courses]
        courses = list(db.courses.find({"_id": {"$in": course_ids}}))
        user["courses"] = parse_json(courses)
        return parse_json(user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users", response_model=UserResponse)
async def create_user(user: UserCreate, admin_user: User = Depends(get_admin_user)):
    try:
        existing = db.users.find_one({"email": user.email})
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
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


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, user_update: UserUpdate, admin_user: User = Depends(get_admin_user)):
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
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
        updated_user = db.users.find_one({"_id": ObjectId(user_id)})
        return parse_json(updated_user)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")
        existing = db.users.find_one({"_id": ObjectId(user_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")
        if str(existing["_id"]) == str(admin_user.id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")
        db.users.delete_one({"_id": ObjectId(user_id)})
        db.user_courses.delete_many({"user_id": ObjectId(user_id)})
        db.progress.delete_many({"user_id": ObjectId(user_id)})
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== ENROLLMENTS ====================

@router.get("/enrollments/pending", response_model=Dict[str, Any])
async def get_pending_enrollments(
    admin_user: User = Depends(get_admin_user),
    course_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
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


@router.post("/enrollments/{enrollment_id}/approve", response_model=Dict[str, Any])
async def approve_enrollment(
    enrollment_id: str,
    body: dict = {},
    admin_user: User = Depends(get_admin_user),
):
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
        }},
    )
    return {"message": "Student approved. Assign them to a class to make active.", "enrollment_id": enrollment_id}


@router.post("/enrollments/{enrollment_id}/reject", response_model=Dict[str, Any])
async def reject_enrollment(
    enrollment_id: str,
    body: dict = {},
    admin_user: User = Depends(get_admin_user),
):
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
        }},
    )
    return {"message": "Student rejected.", "enrollment_id": enrollment_id}


@router.post("/enrollments/assign", response_model=Dict[str, Any])
async def assign_student(body: dict, admin_user: User = Depends(get_admin_user)):
    user_id = body.get("user_id")
    course_id = body.get("course_id")
    class_id = body.get("class_id")

    for field, val in [("user_id", user_id), ("course_id", course_id), ("class_id", class_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required and must be valid")

    user_oid = ObjectId(user_id)
    course_oid = ObjectId(course_id)
    class_oid = ObjectId(class_id)

    if not db.users.find_one({"_id": user_oid}):
        raise HTTPException(status_code=404, detail="Student not found")
    if not db.courses.find_one({"_id": course_oid}):
        raise HTTPException(status_code=404, detail="Course not found")
    if not db.classes.find_one({"_id": class_oid}):
        raise HTTPException(status_code=404, detail="Class not found")

    now = datetime.utcnow()
    db.user_courses.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {
            "$set": {
                "class_id": class_oid,
                "status": "active",
                "enrolled_at": now,
                "approved_by": ObjectId(admin_user.id),
                "admin_note": body.get("note", ""),
                "updated_at": now,
            },
            "$setOnInsert": {"created_at": now},
        },
        upsert=True,
    )
    db.classes.update_one({"_id": class_oid}, {"$addToSet": {"students": user_oid}})
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
    return {"message": "Student assigned and activated.", "user_id": user_id, "course_id": course_id, "class_id": class_id}


@router.post("/enrollments/reassign", response_model=Dict[str, Any])
async def reassign_student(body: dict, admin_user: User = Depends(get_admin_user)):
    user_id = body.get("user_id")
    course_id = body.get("course_id")
    new_class_id = body.get("new_class_id")

    for field, val in [("user_id", user_id), ("course_id", course_id), ("new_class_id", new_class_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required")

    user_oid = ObjectId(user_id)
    course_oid = ObjectId(course_id)
    new_class_oid = ObjectId(new_class_id)

    rec = db.user_courses.find_one({"user_id": user_oid, "course_id": course_oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    if rec.get("status") != "active":
        raise HTTPException(status_code=400, detail="Student is not currently active in this course")
    if not db.classes.find_one({"_id": new_class_oid}):
        raise HTTPException(status_code=404, detail="New class not found")

    old_class_oid = rec.get("class_id")
    if old_class_oid:
        db.classes.update_one({"_id": old_class_oid}, {"$pull": {"students": user_oid}})
    db.classes.update_one({"_id": new_class_oid}, {"$addToSet": {"students": user_oid}})
    db.user_courses.update_one(
        {"user_id": user_oid, "course_id": course_oid},
        {"$set": {
            "class_id": new_class_oid,
            "reassigned_at": datetime.utcnow(),
            "reassigned_by": ObjectId(admin_user.id),
            "reassign_reason": body.get("reason", ""),
        }},
    )
    return {
        "message": "Student reassigned successfully.",
        "user_id": user_id,
        "course_id": course_id,
        "new_class_id": new_class_id,
        "old_class_id": str(old_class_oid) if old_class_oid else None,
    }


@router.post("/enrollments/remove", response_model=Dict[str, Any])
async def remove_student_from_class(body: dict, admin_user: User = Depends(get_admin_user)):
    user_id = body.get("user_id")
    course_id = body.get("course_id")

    for field, val in [("user_id", user_id), ("course_id", course_id)]:
        if not val or not ObjectId.is_valid(val):
            raise HTTPException(status_code=400, detail=f"{field} is required")

    user_oid = ObjectId(user_id)
    course_oid = ObjectId(course_id)
    rec = db.user_courses.find_one({"user_id": user_oid, "course_id": course_oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Enrollment not found")

    old_class_oid = rec.get("class_id")
    remove_course = body.get("remove_from_course", False)

    if old_class_oid:
        db.classes.update_one({"_id": old_class_oid}, {"$pull": {"students": user_oid}})

    if remove_course:
        db.user_courses.update_one(
            {"user_id": user_oid, "course_id": course_oid},
            {"$set": {
                "status": "removed",
                "class_id": None,
                "removed_at": datetime.utcnow(),
                "removed_by": ObjectId(admin_user.id),
                "removal_reason": body.get("reason", ""),
            }},
        )
        msg = "Student removed from course."
    else:
        db.user_courses.update_one(
            {"user_id": user_oid, "course_id": course_oid},
            {"$set": {
                "status": "approved",
                "class_id": None,
                "removed_from_class_at": datetime.utcnow(),
                "removal_reason": body.get("reason", ""),
            }},
        )
        msg = "Student removed from class. They remain enrolled — assign a new class."

    return {"message": msg, "user_id": user_id, "course_id": course_id}


@router.get("/enrollments", response_model=Dict[str, Any])
async def list_all_enrollments(
    admin_user: User = Depends(get_admin_user),
    status: Optional[str] = None,
    course_id: Optional[str] = None,
    class_id: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
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
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "student"}},
        {"$lookup": {"from": "courses", "localField": "course_id", "foreignField": "_id", "as": "course"}},
        {"$lookup": {"from": "classes", "localField": "class_id", "foreignField": "_id", "as": "class"}},
        {"$unwind": {"path": "$student", "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$course", "preserveNullAndEmptyArrays": True}},
        {"$unwind": {"path": "$class", "preserveNullAndEmptyArrays": True}},
    ]

    if search:
        pipeline.append({"$match": {"$or": [
            {"student.first_name": {"$regex": search, "$options": "i"}},
            {"student.last_name": {"$regex": search, "$options": "i"}},
            {"student.email": {"$regex": search, "$options": "i"}},
        ]}})

    pipeline += [
        {"$skip": skip},
        {"$limit": limit},
        {"$project": {
            "status": 1, "created_at": 1, "enrolled_at": 1, "approved_at": 1, "admin_note": 1,
            "student_id": "$student._id",
            "student_name": {"$concat": ["$student.first_name", " ", "$student.last_name"]},
            "student_email": "$student.email",
            "course_name": "$course.name",
            "course_id": 1,
            "class_title": "$class.title",
            "class_id": 1,
        }},
    ]

    results = list(db.user_courses.aggregate(pipeline))
    total = db.user_courses.count_documents(match)
    counts = {
        s: db.user_courses.count_documents({"status": s})
        for s in ("pending", "approved", "active", "rejected", "removed")
    }
    return {"enrollments": parse_json(results), "total": total, "counts": counts}


# ==================== CLASSES ====================

@router.get("/classes", response_model=Dict[str, Any])
async def admin_get_classes(
    admin_user: User = Depends(get_admin_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=200),
    search: Optional[str] = None,
    course_id: Optional[str] = None,
):
    skip = (page - 1) * limit
    query: dict = {}
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
    if course_id and ObjectId.is_valid(course_id):
        query["course_id"] = ObjectId(course_id)

    classes = list(db.classes.find(query).sort("date", -1).skip(skip).limit(limit))
    total = db.classes.count_documents(query)

    for cls in classes:
        if cls.get("course_id"):
            course = db.courses.find_one({"_id": cls["course_id"]})
            if course:
                cls["course"] = {"_id": str(course["_id"]), "name": course.get("name", course.get("title", ""))}
        if cls.get("instructor_id"):
            inst = db.users.find_one({"_id": cls["instructor_id"]})
            if inst:
                cls["instructor"] = {
                    "_id": str(inst["_id"]),
                    "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                    "email": inst.get("email", ""),
                }
        cls["students_count"] = len(cls.get("students", []))

    return {
        "classes": parse_json(classes),
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": max(1, -(-total // limit)),
    }


@router.post("/classes", response_model=Dict[str, Any])
async def admin_create_class(body: dict, admin_user: User = Depends(get_admin_user)):
    required = ["course_id", "title", "date", "duration", "meet_link"]
    for field in required:
        if not body.get(field):
            raise HTTPException(status_code=400, detail=f"{field} is required")
    if not ObjectId.is_valid(body["course_id"]):
        raise HTTPException(status_code=400, detail="Invalid course_id")
    if not db.courses.find_one({"_id": ObjectId(body["course_id"])}):
        raise HTTPException(status_code=404, detail="Course not found")
    if isinstance(body.get("date"), str):
        try:
            body["date"] = datetime.fromisoformat(body["date"].replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use ISO 8601.")

    class_doc = {
        "course_id": ObjectId(body["course_id"]),
        "title": body["title"],
        "description": body.get("description", ""),
        "date": body["date"],
        "duration": int(body.get("duration", 60)),
        "meet_link": body["meet_link"],
        "recording_link": body.get("recording_link", ""),
        "materials": body.get("materials", []),
        "students": [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    if body.get("instructor_id") and ObjectId.is_valid(body["instructor_id"]):
        class_doc["instructor_id"] = ObjectId(body["instructor_id"])

    result = db.classes.insert_one(class_doc)
    created = db.classes.find_one({"_id": result.inserted_id})
    return parse_json(created)


@router.get("/classes/{class_id}/students", response_model=Dict[str, Any])
async def get_class_students(class_id: str, admin_user: User = Depends(get_admin_user)):
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
        progress = db.progress.find_one({"user_id": s["_id"], "course_id": class_doc.get("course_id")})
        result.append({
            "student_id": str(s["_id"]),
            "name": f"{s.get('first_name','')} {s.get('last_name','')}".strip(),
            "email": s.get("email"),
            "phone": s.get("phone"),
            "enrolled_at": enrollment.get("enrolled_at").isoformat() if enrollment and enrollment.get("enrolled_at") else None,
            "progress_pct": progress.get("percentage", 0) if progress else 0,
            "last_active": progress.get("last_active").isoformat() if progress and progress.get("last_active") else None,
        })

    return {"class_id": class_id, "class_title": class_doc.get("title"), "student_count": len(result), "students": result}


@router.get("/classes/{class_id}", response_model=Dict[str, Any])
async def admin_get_class(class_id: str, admin_user: User = Depends(get_admin_user)):
    if not ObjectId.is_valid(class_id):
        raise HTTPException(status_code=400, detail="Invalid class ID")
    cls = db.classes.find_one({"_id": ObjectId(class_id)})
    if not cls:
        raise HTTPException(status_code=404, detail="Class not found")
    if cls.get("course_id"):
        course = db.courses.find_one({"_id": cls["course_id"]})
        if course:
            cls["course"] = {"_id": str(course["_id"]), "name": course.get("name", course.get("title", ""))}
    if cls.get("instructor_id"):
        inst = db.users.find_one({"_id": cls["instructor_id"]})
        if inst:
            cls["instructor"] = {
                "_id": str(inst["_id"]),
                "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                "email": inst.get("email", ""),
            }
    return parse_json(cls)


@router.put("/classes/{class_id}", response_model=Dict[str, Any])
async def admin_update_class(class_id: str, body: dict, admin_user: User = Depends(get_admin_user)):
    if not ObjectId.is_valid(class_id):
        raise HTTPException(status_code=400, detail="Invalid class ID")
    existing = db.classes.find_one({"_id": ObjectId(class_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Class not found")

    for field in ("_id", "students", "created_at"):
        body.pop(field, None)
    if body.get("course_id") and ObjectId.is_valid(str(body["course_id"])):
        body["course_id"] = ObjectId(body["course_id"])
    if body.get("instructor_id") and ObjectId.is_valid(str(body["instructor_id"])):
        body["instructor_id"] = ObjectId(body["instructor_id"])
    elif "instructor_id" in body and not body["instructor_id"]:
        body["instructor_id"] = None
    if isinstance(body.get("date"), str):
        try:
            body["date"] = datetime.fromisoformat(body["date"].replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")
    if "duration" in body:
        body["duration"] = int(body["duration"] or 60)
    body["updated_at"] = datetime.utcnow()

    db.classes.update_one({"_id": ObjectId(class_id)}, {"$set": body})
    updated = db.classes.find_one({"_id": ObjectId(class_id)})
    return parse_json(updated)


@router.delete("/classes/{class_id}", response_model=Dict[str, Any])
async def admin_delete_class(class_id: str, admin_user: User = Depends(get_admin_user)):
    if not ObjectId.is_valid(class_id):
        raise HTTPException(status_code=400, detail="Invalid class ID")
    existing = db.classes.find_one({"_id": ObjectId(class_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Class not found")
    db.user_courses.update_many(
        {"class_id": ObjectId(class_id)},
        {"$set": {"class_id": None, "status": "approved"}},
    )
    db.classes.delete_one({"_id": ObjectId(class_id)})
    return {"success": True, "message": "Class deleted successfully"}


# ==================== COURSES ====================

@router.get("/courses", response_model=Dict[str, Any])
async def get_all_courses(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    level: Optional[str] = None,
    search: Optional[str] = None,
):
    try:
        query: dict = {}
        if level:
            query["level"] = level
        if search:
            query["$or"] = [
                {"name": {"$regex": search, "$options": "i"}},
                {"title": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}},
            ]
        courses = list(db.courses.find(query).skip(skip).limit(limit))
        total = db.courses.count_documents(query)
        for course in courses:
            course.setdefault("title", course.get("name", ""))
            course.setdefault("name", course.get("title", ""))
            if course.get("instructor_id"):
                inst = db.users.find_one({"_id": course["instructor_id"]})
                if inst:
                    course["instructor"] = {
                        "id": str(inst["_id"]),
                        "name": f"{inst.get('first_name','')} {inst.get('last_name','')}".strip(),
                        "email": inst.get("email", ""),
                    }
            course["enrollment_count"] = db.user_courses.count_documents({
                "course_id": course["_id"], "status": "active"
            })
        return {"courses": parse_json(courses), "total": total, "skip": skip, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/courses/{course_id}", response_model=Dict[str, Any])
async def get_course_by_id(course_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(course_id):
            raise HTTPException(status_code=400, detail="Invalid course ID")
        course = db.courses.find_one({"_id": ObjectId(course_id)})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        if course.get("instructor_id"):
            instructor = db.users.find_one({"_id": course["instructor_id"]})
            if instructor:
                course["instructor"] = {
                    "id": str(instructor["_id"]),
                    "name": f"{instructor.get('first_name', '')} {instructor.get('last_name', '')}",
                    "email": instructor.get("email", ""),
                }
        enrollments = list(db.user_courses.find({"course_id": ObjectId(course_id)}))
        student_ids = [e["user_id"] for e in enrollments]
        students = list(db.users.find({"_id": {"$in": student_ids}}))
        course["students"] = [
            {
                "id": str(s["_id"]),
                "name": f"{s.get('first_name', '')} {s.get('last_name', '')}",
                "email": s.get("email", ""),
                "enrollment_date": next((e.get("enrolled_at") for e in enrollments if e["user_id"] == s["_id"]), None),
            }
            for s in students
        ]
        course["classes"] = parse_json(list(db.classes.find({"course_id": ObjectId(course_id)}).sort("date", 1)))
        course["assignments"] = parse_json(list(db.assignments.find({"course_id": ObjectId(course_id)}).sort("due_date", 1)))
        return parse_json(course)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/courses", response_model=Dict[str, Any])
async def admin_create_course(body: dict, admin_user: User = Depends(get_admin_user)):
    if "title" in body and "name" not in body:
        body["name"] = body["title"]
    if "name" in body and "title" not in body:
        body["title"] = body["name"]
    body["created_at"] = datetime.utcnow()
    body["updated_at"] = datetime.utcnow()
    if body.get("instructor_id") and ObjectId.is_valid(body["instructor_id"]):
        body["instructor_id"] = ObjectId(body["instructor_id"])
    if "duration" in body:
        body["duration"] = int(body["duration"] or 0)
    result = db.courses.insert_one(body)
    created = db.courses.find_one({"_id": result.inserted_id})
    return parse_json(created)


@router.put("/courses/{course_id}", response_model=Dict[str, Any])
async def admin_update_course(course_id: str, body: dict, admin_user: User = Depends(get_admin_user)):
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
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


@router.delete("/courses/{course_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_course(course_id: str, admin_user: User = Depends(get_admin_user)):
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


@router.post("/courses/{course_id}/enroll/{user_id}")
async def enroll_user_in_course(course_id: str, user_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(course_id) or not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid ID format")
        if not db.courses.find_one({"_id": ObjectId(course_id)}):
            raise HTTPException(status_code=404, detail="Course not found")
        if not db.users.find_one({"_id": ObjectId(user_id)}):
            raise HTTPException(status_code=404, detail="User not found")
        existing = db.user_courses.find_one({"user_id": ObjectId(user_id), "course_id": ObjectId(course_id)})
        if existing:
            return {"message": "User already enrolled in this course"}
        db.user_courses.insert_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id),
            "enrolled_at": datetime.utcnow(),
            "status": "active",
        })
        db.progress.insert_one({
            "user_id": ObjectId(user_id),
            "course_id": ObjectId(course_id),
            "percentage": 0,
            "modules_completed": [],
            "last_activity": datetime.utcnow(),
        })
        return {"message": "User successfully enrolled in course"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/courses/{course_id}/enroll/{user_id}")
async def remove_user_from_course(course_id: str, user_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(course_id) or not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid ID format")
        enrollment = db.user_courses.find_one({"user_id": ObjectId(user_id), "course_id": ObjectId(course_id)})
        if not enrollment:
            raise HTTPException(status_code=404, detail="Enrollment not found")
        db.user_courses.delete_one({"user_id": ObjectId(user_id), "course_id": ObjectId(course_id)})
        db.progress.delete_one({"user_id": ObjectId(user_id), "course_id": ObjectId(course_id)})
        return {"message": "User successfully removed from course"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/courses/{course_id}/students", response_model=Dict[str, Any])
async def get_course_students(
    course_id: str,
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    if not ObjectId.is_valid(course_id):
        raise HTTPException(status_code=400, detail="Invalid course ID")
    course = db.courses.find_one({"_id": ObjectId(course_id)})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    enrollments = list(db.user_courses.find({"course_id": ObjectId(course_id)}).skip(skip).limit(limit))
    total = db.user_courses.count_documents({"course_id": ObjectId(course_id)})

    result = []
    for enc in enrollments:
        student = db.users.find_one({"_id": enc.get("user_id")})
        if not student:
            continue
        class_doc = db.classes.find_one({"_id": enc.get("class_id")}) if enc.get("class_id") else None
        progress = db.progress.find_one({"user_id": enc["user_id"], "course_id": ObjectId(course_id)})
        result.append({
            "enrollment_id": str(enc["_id"]),
            "status": enc.get("status", "pending"),
            "enrolled_at": enc.get("enrolled_at").isoformat() if enc.get("enrolled_at") else None,
            "student_id": str(student["_id"]),
            "name": f"{student.get('first_name','')} {student.get('last_name','')}".strip(),
            "email": student.get("email", ""),
            "phone": student.get("phone", ""),
            "class_id": str(enc["class_id"]) if enc.get("class_id") else None,
            "class_title": class_doc.get("title") if class_doc else None,
            "progress_pct": progress.get("percentage", 0) if progress else 0,
            "last_active": progress.get("last_active").isoformat() if progress and progress.get("last_active") else None,
        })

    return {"course_id": course_id, "course_name": course.get("name", course.get("title", "")), "students": result, "total": total, "skip": skip, "limit": limit}


# ==================== ADMISSION INQUIRIES ====================

@router.get("/admission-inquiries", response_model=Dict[str, Any])
async def get_admission_inquiries(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    program: Optional[str] = None,
    location: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: int = -1,
):
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
                {"phone": {"$regex": search, "$options": "i"}},
            ]
        inquiries = list(db.admission_inquiries.find(query).sort(sort_by, sort_order).skip(skip).limit(limit))
        total = db.admission_inquiries.count_documents(query)
        status_stats = list(db.admission_inquiries.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]))
        program_stats = list(db.admission_inquiries.aggregate([{"$group": {"_id": "$program", "count": {"$sum": 1}}}]))
        location_stats = list(db.admission_inquiries.aggregate([{"$group": {"_id": "$location", "count": {"$sum": 1}}}]))
        return {
            "inquiries": parse_json(inquiries),
            "pagination": {"total": total, "skip": skip, "limit": limit, "has_more": skip + limit < total},
            "statistics": {
                "by_status": parse_json(status_stats),
                "by_program": parse_json(program_stats),
                "by_location": parse_json(location_stats),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admission-inquiries/stats/summary", response_model=Dict[str, Any])
async def get_admission_stats(admin_user: User = Depends(get_admin_user)):
    try:
        total = db.admission_inquiries.count_documents({})
        unread = db.admission_inquiries.count_documents({"is_read": False})
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent = db.admission_inquiries.count_documents({"created_at": {"$gte": thirty_days_ago}})
        return {
            "total": total,
            "unread": unread,
            "recent_30_days": recent,
            "by_status": parse_json(list(db.admission_inquiries.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]))),
            "by_program": parse_json(list(db.admission_inquiries.aggregate([{"$group": {"_id": "$program", "count": {"$sum": 1}}}]))),
            "by_location": parse_json(list(db.admission_inquiries.aggregate([{"$group": {"_id": "$location", "count": {"$sum": 1}}}]))),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admission-inquiries/export/csv")
async def export_inquiries_csv(admin_user: User = Depends(get_admin_user)):
    try:
        inquiries = list(db.admission_inquiries.find().sort("created_at", -1))
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["First Name", "Last Name", "Email", "Phone", "Program", "Location", "Message", "Status", "Created At", "Read"])
        for inquiry in inquiries:
            writer.writerow([
                inquiry.get("first_name", ""), inquiry.get("last_name", ""), inquiry.get("email", ""),
                inquiry.get("phone", ""), inquiry.get("program", ""), inquiry.get("location", ""),
                inquiry.get("message", ""), inquiry.get("status", "pending"), inquiry.get("created_at", ""),
                "Yes" if inquiry.get("is_read") else "No",
            ])
        csv_content = output.getvalue()
        output.close()
        return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=admission_inquiries.csv"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admission-inquiries/{inquiry_id}", response_model=Dict[str, Any])
async def get_admission_inquiry(inquiry_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")
        inquiry = db.admission_inquiries.find_one({"_id": ObjectId(inquiry_id)})
        if not inquiry:
            raise HTTPException(status_code=404, detail="Inquiry not found")
        db.admission_inquiries.update_one({"_id": ObjectId(inquiry_id)}, {"$set": {"is_read": True}})
        return parse_json(inquiry)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/admission-inquiries/{inquiry_id}/status")
async def update_inquiry_status(inquiry_id: str, status_data: dict, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")
        new_status = status_data.get("status")
        if not new_status or new_status not in ["pending", "contacted", "enrolled"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status. Must be one of: pending, contacted, enrolled")
        result = db.admission_inquiries.update_one(
            {"_id": ObjectId(inquiry_id)},
            {"$set": {"status": new_status, "updated_at": datetime.utcnow()}},
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")
        return {"message": f"Inquiry status updated to {new_status}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/admission-inquiries/{inquiry_id}/notes")
async def add_inquiry_note(inquiry_id: str, note_data: dict, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(inquiry_id):
            raise HTTPException(status_code=400, detail="Invalid inquiry ID")
        note = note_data.get("note")
        if not note:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Note is required")
        note_obj = {
            "note": note,
            "created_by": str(admin_user.id),
            "created_by_name": f"{admin_user.first_name} {admin_user.last_name}",
            "created_at": datetime.utcnow(),
        }
        result = db.admission_inquiries.update_one(
            {"_id": ObjectId(inquiry_id)},
            {"$push": {"admin_notes": note_obj}, "$set": {"updated_at": datetime.utcnow()}},
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")
        return {"message": "Note added successfully", "note": note_obj}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/admission-inquiries/{inquiry_id}")
async def delete_admission_inquiry(inquiry_id: str, admin_user: User = Depends(get_admin_user)):
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


# ==================== CAREERS ====================

@router.get("/careers/stats", response_model=Dict[str, Any])
async def admin_get_careers_stats(admin_user: User = Depends(get_admin_user)):
    try:
        total_jobs = db.job_listings.count_documents({})
        published_jobs = db.job_listings.count_documents({"is_published": True})
        featured_jobs = db.job_listings.count_documents({"is_featured": True})
        total_applications = db.job_applications.count_documents({})
        applications_by_status = list(db.job_applications.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}, {"$sort": {"_id": 1}}]))
        categories = list(db.job_categories.find())
        for category in categories:
            category["job_count"] = db.job_listings.count_documents({"category": category["name"], "is_published": True})
        recent_jobs = list(db.job_listings.find().sort("created_at", -1).limit(5))
        recent_applications = list(db.job_applications.find().sort("created_at", -1).limit(5))
        for app in recent_applications:
            job = db.job_listings.find_one({"_id": app["job_id"]})
            if job:
                app["job"] = {"id": str(job["_id"]), "title": job["title"], "company": job["company"]}
        return {
            "job_stats": {"total": total_jobs, "published": published_jobs, "featured": featured_jobs},
            "application_stats": {"total": total_applications, "by_status": parse_json(applications_by_status)},
            "categories": parse_json(categories),
            "recent_activity": {"jobs": parse_json(recent_jobs), "applications": parse_json(recent_applications)},
            "top_jobs": {
                "by_views": parse_json(list(db.job_listings.find().sort("views", -1).limit(5))),
                "by_applications": parse_json(list(db.job_listings.find().sort("applications_count", -1).limit(5))),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/careers/jobs", response_model=Dict[str, Any])
async def admin_get_job_listings(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    category: Optional[str] = None,
    is_published: Optional[bool] = None,
    search: Optional[str] = None,
):
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
                {"description": {"$regex": search, "$options": "i"}},
            ]
        jobs = list(db.job_listings.find(query).sort("created_at", -1).skip(skip).limit(limit))
        total = db.job_listings.count_documents(query)
        for job in jobs:
            job["applications_count"] = db.job_applications.count_documents({"job_id": job["_id"]})
        return {"jobs": parse_json(jobs), "total": total, "skip": skip, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/careers/jobs", response_model=JobListingResponse)
async def admin_create_job_listing(job: JobListingCreate, admin_user: User = Depends(get_admin_user)):
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


@router.put("/careers/jobs/{job_id}", response_model=JobListingResponse)
async def admin_update_job_listing(job_id: str, job_update: JobListingUpdate, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(job_id):
            raise HTTPException(status_code=400, detail="Invalid job ID")
        existing = db.job_listings.find_one({"_id": ObjectId(job_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Job listing not found")
        update_data = job_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()
        db.job_listings.update_one({"_id": ObjectId(job_id)}, {"$set": update_data})
        return parse_json(db.job_listings.find_one({"_id": ObjectId(job_id)}))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/careers/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_job_listing(job_id: str, admin_user: User = Depends(get_admin_user)):
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


@router.get("/careers/applications", response_model=Dict[str, Any])
async def admin_get_job_applications(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    job_id: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
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
                {"email": {"$regex": search, "$options": "i"}},
            ]
        applications = list(db.job_applications.find(query).sort("created_at", -1).skip(skip).limit(limit))
        total = db.job_applications.count_documents(query)
        for app in applications:
            job = db.job_listings.find_one({"_id": app["job_id"]})
            if job:
                app["job"] = {"id": str(job["_id"]), "title": job["title"], "company": job["company"]}
        return {"applications": parse_json(applications), "total": total, "skip": skip, "limit": limit}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/careers/applications/{application_id}", response_model=JobApplicationResponse)
async def admin_get_application_details(application_id: str, admin_user: User = Depends(get_admin_user)):
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


@router.put("/careers/applications/{application_id}", response_model=JobApplicationResponse)
async def admin_update_application_status(application_id: str, application_update: JobApplicationUpdate, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(application_id):
            raise HTTPException(status_code=400, detail="Invalid application ID")
        existing = db.job_applications.find_one({"_id": ObjectId(application_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Application not found")
        update_data = application_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()
        db.job_applications.update_one({"_id": ObjectId(application_id)}, {"$set": update_data})
        updated = db.job_applications.find_one({"_id": ObjectId(application_id)})
        job = db.job_listings.find_one({"_id": updated["job_id"]})
        if job:
            updated["job"] = {"id": str(job["_id"]), "title": job["title"], "company": job["company"]}
        return parse_json(updated)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/careers/categories", response_model=List[Dict[str, Any]])
async def admin_get_job_categories(admin_user: User = Depends(get_admin_user)):
    try:
        categories = list(db.job_categories.find().sort("name", 1))
        for category in categories:
            category["job_count"] = db.job_listings.count_documents({"category": category["name"]})
        return parse_json(categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/careers/categories", response_model=JobCategory)
async def admin_create_job_category(category: JobCategoryCreate, admin_user: User = Depends(get_admin_user)):
    try:
        existing = db.job_categories.find_one({"name": category.name})
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Category already exists")
        category_data = category.dict()
        category_data["created_at"] = datetime.utcnow()
        category_data["updated_at"] = datetime.utcnow()
        category_data["job_count"] = 0
        result = db.job_categories.insert_one(category_data)
        return parse_json(db.job_categories.find_one({"_id": result.inserted_id}))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/careers/categories/{category_id}", response_model=JobCategory)
async def admin_update_job_category(category_id: str, category_update: JobCategoryUpdate, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(category_id):
            raise HTTPException(status_code=400, detail="Invalid category ID")
        existing = db.job_categories.find_one({"_id": ObjectId(category_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Category not found")
        update_data = category_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()
        db.job_categories.update_one({"_id": ObjectId(category_id)}, {"$set": update_data})
        if "name" in update_data and update_data["name"] != existing["name"]:
            db.job_listings.update_many({"category": existing["name"]}, {"$set": {"category": update_data["name"]}})
        updated = db.job_categories.find_one({"_id": ObjectId(category_id)})
        updated["job_count"] = db.job_listings.count_documents({"category": updated["name"]})
        return parse_json(updated)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/careers/categories/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_job_category(category_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(category_id):
            raise HTTPException(status_code=400, detail="Invalid category ID")
        existing = db.job_categories.find_one({"_id": ObjectId(category_id)})
        if not existing:
            raise HTTPException(status_code=404, detail="Category not found")
        job_count = db.job_listings.count_documents({"category": existing["name"]})
        if job_count > 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot delete category with {job_count} job listings.")
        db.job_categories.delete_one({"_id": ObjectId(category_id)})
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== DASHBOARD STATS ====================

@router.get("/dashboard/stats", response_model=Dict[str, Any])
async def get_admin_dashboard_stats(admin_user: User = Depends(get_admin_user)):
    try:
        return {
            "users": {
                "total": db.users.count_documents({}),
                "active": db.users.count_documents({"disabled": False}),
                "by_role": parse_json(list(db.users.aggregate([{"$group": {"_id": "$role", "count": {"$sum": 1}}}]))),
            },
            "courses": {
                "total": db.courses.count_documents({}),
                "enrollments": db.user_courses.count_documents({}),
                "by_level": parse_json(list(db.courses.aggregate([{"$group": {"_id": "$level", "count": {"$sum": 1}}}]))),
            },
            "blog": {
                "total_posts": db.blog_posts.count_documents({}),
                "total_comments": db.comments.count_documents({}),
                "by_category": parse_json(list(db.blog_posts.aggregate([{"$group": {"_id": "$category", "count": {"$sum": 1}}}]))),
            },
            "careers": {
                "total_jobs": db.job_listings.count_documents({}),
                "total_applications": db.job_applications.count_documents({}),
                "by_category": parse_json(list(db.job_listings.aggregate([{"$group": {"_id": "$category", "count": {"$sum": 1}}}]))),
            },
            "contacts": {
                "total": db.contact_submissions.count_documents({}),
                "unread": db.contact_submissions.count_documents({"is_read": False}),
            },
            "admissions": {
                "total": db.admission_inquiries.count_documents({}),
                "unread": db.admission_inquiries.count_documents({"is_read": False}),
                "by_status": parse_json(list(db.admission_inquiries.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]))),
            },
            "recent": {
                "users": parse_json(list(db.users.find().sort("created_at", -1).limit(5))),
                "applications": parse_json(list(db.job_applications.find().sort("created_at", -1).limit(5))),
                "inquiries": parse_json(list(db.admission_inquiries.find().sort("created_at", -1).limit(5))),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CONTACT SUBMISSIONS ====================

@router.get("/contact-submissions/list", response_model=Dict[str, Any])
async def get_all_contact_submissions(
    admin_user: User = Depends(get_admin_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    read_status: Optional[bool] = None,
    sort_by: str = "created_at",
    sort_order: int = -1,
):
    try:
        query = {}
        if read_status is not None:
            query["is_read"] = read_status
        submissions = list(db.contact_submissions.find(query).sort(sort_by, sort_order).skip(skip).limit(limit))
        total = db.contact_submissions.count_documents(query)
        return {"data": parse_json(submissions), "pagination": {"total": total, "skip": skip, "limit": limit, "has_more": skip + limit < total}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/contact-submissions/{submission_id}", response_model=Dict[str, Any])
async def get_contact_submission_details(submission_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(submission_id):
            raise HTTPException(status_code=400, detail="Invalid submission ID")
        submission = db.contact_submissions.find_one({"_id": ObjectId(submission_id)})
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        db.contact_submissions.update_one({"_id": ObjectId(submission_id)}, {"$set": {"is_read": True}})
        return parse_json(submission)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/contact-submissions/{submission_id}/read")
async def mark_submission_read(submission_id: str, admin_user: User = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(submission_id):
            raise HTTPException(status_code=400, detail="Invalid submission ID")
        result = db.contact_submissions.update_one({"_id": ObjectId(submission_id)}, {"$set": {"is_read": True}})
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Submission not found")
        return {"success": True, "message": "Submission marked as read"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/contact-submissions/{submission_id}")
async def delete_submission(submission_id: str, admin_user: User = Depends(get_admin_user)):
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
