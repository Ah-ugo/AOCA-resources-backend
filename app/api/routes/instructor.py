from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from typing import Dict, Any, Optional, List
from datetime import datetime
from bson import ObjectId
import json

from .common import (
    User,
    get_current_active_user,
    get_instructor_user,
    parse_json,
    db,
)

router = APIRouter()


# ==================== WEBSOCKET ====================


class ConnectionManager:
    def __init__(self):
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


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
                if payload.get("text") and payload.get("chatId"):
                    db.messages.insert_one(
                        {
                            "sender_id": ObjectId(user_id),
                            "recipient_id": ObjectId(payload["chatId"]),
                            "text": payload["text"],
                            "is_read": False,
                            "created_at": datetime.utcnow(),
                        }
                    )
                await manager.send_personal_message(
                    data, payload.get("chatId", user_id)
                )
            except Exception:
                await manager.send_personal_message(data, user_id)
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)


# ==================== INSTRUCTOR DASHBOARD ====================


@router.get("/dashboard/stats", response_model=Dict[str, Any])
async def get_instructor_stats(current_user: User = Depends(get_instructor_user)):
    """Instructor dashboard statistics."""
    try:
        user_oid = ObjectId(str(current_user.id))
        total_courses = db.courses.count_documents({"instructor_id": user_oid})
        instructor_courses = list(
            db.courses.find({"instructor_id": user_oid}, {"_id": 1})
        )
        course_ids = [c["_id"] for c in instructor_courses]

        total_students = db.user_courses.count_documents(
            {"course_id": {"$in": course_ids}, "status": "active"}
        )
        total_assignments = db.assignments.count_documents(
            {"course_id": {"$in": course_ids}}
        )

        pending_grading = 0
        for assignment in db.assignments.find({"course_id": {"$in": course_ids}}):
            for sub in assignment.get("submissions", []):
                if not sub.get("grade"):
                    pending_grading += 1

        recent_enrollments = list(
            db.user_courses.aggregate(
                [
                    {"$match": {"course_id": {"$in": course_ids}, "status": "active"}},
                    {"$sort": {"enrolled_at": -1}},
                    {"$limit": 5},
                    {
                        "$lookup": {
                            "from": "users",
                            "localField": "user_id",
                            "foreignField": "_id",
                            "as": "student",
                        }
                    },
                    {
                        "$lookup": {
                            "from": "courses",
                            "localField": "course_id",
                            "foreignField": "_id",
                            "as": "course",
                        }
                    },
                    {
                        "$unwind": {
                            "path": "$student",
                            "preserveNullAndEmptyArrays": True,
                        }
                    },
                    {
                        "$unwind": {
                            "path": "$course",
                            "preserveNullAndEmptyArrays": True,
                        }
                    },
                    {
                        "$project": {
                            "student_name": {
                                "$concat": [
                                    "$student.first_name",
                                    " ",
                                    "$student.last_name",
                                ]
                            },
                            "course_name": "$course.name",
                            "enrolled_at": 1,
                        }
                    },
                ]
            )
        )

        return {
            "stats": {
                "total_courses": total_courses,
                "total_students": total_students,
                "total_assignments": total_assignments,
                "pending_grading": pending_grading,
            },
            "recent_enrollments": parse_json(recent_enrollments),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/courses", response_model=List[Dict[str, Any]])
async def get_instructor_courses(current_user: User = Depends(get_instructor_user)):
    """Get all courses for the current instructor."""
    try:
        user_oid = ObjectId(str(current_user.id))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    instructor_match = {
        "$or": [
            {"instructor_id": user_oid},
            {"instructor_id": str(current_user.id)},
            {"instructor_id": current_user.id},
        ]
    }

    courses = list(db.courses.find(instructor_match))
    for c in courses:
        c.setdefault("title", c.get("name", ""))
        c["enrollment_count"] = db.user_courses.count_documents(
            {"course_id": c["_id"], "status": "active"}
        )
    return parse_json(courses)


# ==================== MESSAGES ====================


@router.get("/conversations", response_model=Dict[str, Any], tags=["messages"])
async def get_conversations(current_user: User = Depends(get_current_active_user)):
    """Return all conversations for the current user."""
    user_oid = ObjectId(str(current_user.id))

    sent_to = db.messages.distinct("recipient_id", {"sender_id": user_oid})
    received = db.messages.distinct("sender_id", {"recipient_id": user_oid})
    partner_ids = list({str(u) for u in sent_to + received})

    conversations = []
    for pid in partner_ids:
        if not ObjectId.is_valid(pid):
            continue
        partner = db.users.find_one({"_id": ObjectId(pid)})
        if not partner:
            continue

        last_msg = db.messages.find_one(
            {
                "$or": [
                    {"sender_id": user_oid, "recipient_id": ObjectId(pid)},
                    {"sender_id": ObjectId(pid), "recipient_id": user_oid},
                ]
            },
            sort=[("created_at", -1)],
        )
        unread_count = db.messages.count_documents(
            {
                "sender_id": ObjectId(pid),
                "recipient_id": user_oid,
                "is_read": False,
            }
        )

        conversations.append(
            {
                "id": pid,
                "name": f"{partner.get('first_name','')} {partner.get('last_name','')}".strip(),
                "role": partner.get("role", ""),
                "lastMessage": last_msg.get("text", "") if last_msg else "",
                "unread": unread_count,
                "updated_at": (
                    last_msg.get("created_at").isoformat()
                    if last_msg and last_msg.get("created_at")
                    else None
                ),
            }
        )

    conversations.sort(key=lambda c: c.get("updated_at") or "", reverse=True)
    return {"conversations": conversations}


@router.get(
    "/conversations/{partner_id}", response_model=Dict[str, Any], tags=["messages"]
)
async def get_conversation_messages(
    partner_id: str,
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Return all messages between current user and a specific partner."""
    if not ObjectId.is_valid(partner_id):
        raise HTTPException(status_code=400, detail="Invalid partner ID")

    user_oid = ObjectId(str(current_user.id))
    partner_oid = ObjectId(partner_id)

    msgs = list(
        db.messages.find(
            {
                "$or": [
                    {"sender_id": user_oid, "recipient_id": partner_oid},
                    {"sender_id": partner_oid, "recipient_id": user_oid},
                ]
            }
        )
        .sort("created_at", 1)
        .skip(skip)
        .limit(limit)
    )

    db.messages.update_many(
        {"sender_id": partner_oid, "recipient_id": user_oid, "is_read": False},
        {"$set": {"is_read": True}},
    )

    formatted = [
        {
            "id": str(m["_id"]),
            "text": m.get("text", ""),
            "senderId": str(m.get("sender_id", "")),
            "chatId": partner_id,
            "timestamp": (
                m.get("created_at").isoformat() if m.get("created_at") else None
            ),
        }
        for m in msgs
    ]
    return {"messages": formatted, "chatId": partner_id}


@router.post("/send", response_model=Dict[str, Any], tags=["messages"])
async def send_message(
    body: dict,
    current_user: User = Depends(get_current_active_user),
):
    """Persist a message."""
    recipient_id = body.get("recipient_id")
    text = (body.get("text") or "").strip()

    if not recipient_id or not ObjectId.is_valid(recipient_id):
        raise HTTPException(status_code=400, detail="recipient_id required")
    if not text:
        raise HTTPException(status_code=400, detail="text required")

    msg = {
        "sender_id": ObjectId(str(current_user.id)),
        "recipient_id": ObjectId(recipient_id),
        "text": text,
        "is_read": False,
        "created_at": datetime.utcnow(),
    }
    result = db.messages.insert_one(msg)

    return {
        "id": str(result.inserted_id),
        "text": text,
        "senderId": str(current_user.id),
        "chatId": recipient_id,
        "timestamp": msg["created_at"].isoformat(),
    }
