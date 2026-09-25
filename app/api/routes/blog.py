from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Dict, Any, Optional, List
from datetime import datetime

from .common import (
    BlogPostCreate, BlogPostUpdate, BlogPostResponse, Comment, CommentCreate,
    User, get_current_active_user, get_current_user,
    parse_json, db,
)
from bson import ObjectId

router = APIRouter()


@router.get("/posts", response_model=Dict[str, Any])
async def get_blog_posts(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    category: Optional[str] = None,
    search: Optional[str] = None,
):
    """Get all published blog posts with pagination and filtering."""
    try:
        query = {"is_published": True}
        if category:
            query["category"] = category
        if search:
            query["$or"] = [
                {"title": {"$regex": search, "$options": "i"}},
                {"excerpt": {"$regex": search, "$options": "i"}},
                {"content": {"$regex": search, "$options": "i"}},
            ]

        posts = list(
            db.blog_posts.find(query).sort("created_at", -1).skip(skip).limit(limit)
        )
        total = db.blog_posts.count_documents(query)

        for post in posts:
            if post.get("author_id"):
                author = db.users.find_one({"_id": ObjectId(post["author_id"])})
                if author:
                    post["author"] = {
                        "name": f"{author.get('first_name', '')} {author.get('last_name', '')}",
                        "role": author.get("role", ""),
                        "image": author.get("image", ""),
                    }

        return {"posts": parse_json(posts), "total": total, "skip": skip, "limit": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/posts/{post_id}", response_model=Dict[str, Any])
async def get_blog_post(post_id: str):
    """Get a single blog post by ID."""
    try:
        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        if post.get("author_id"):
            author = db.users.find_one({"_id": post["author_id"]})
            if author:
                post["author"] = {
                    "name": f"{author.get('first_name', '')} {author.get('last_name', '')}",
                    "role": author.get("role", ""),
                    "image": author.get("image", ""),
                }

        comments = list(
            db.comments.find({"post_id": ObjectId(post_id)}).sort("created_at", -1)
        )
        post["comments"] = parse_json(comments)

        related_posts = list(
            db.blog_posts.find(
                {"category": post["category"], "_id": {"$ne": ObjectId(post_id)}, "is_published": True}
            ).limit(3)
        )
        post["related_posts"] = parse_json(related_posts)

        return parse_json(post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/posts", response_model=BlogPostResponse)
async def create_blog_post(
    post: BlogPostCreate,
    current_user: User = Depends(get_current_active_user),
):
    """Create a new blog post (admin/editor only)."""
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

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


@router.put("/posts/{post_id}", response_model=BlogPostResponse)
async def update_blog_post(
    post_id: str,
    post_update: BlogPostUpdate,
    current_user: User = Depends(get_current_active_user),
):
    """Update a blog post (admin/editor only)."""
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        if not ObjectId.is_valid(post_id):
            raise HTTPException(status_code=400, detail="Invalid post ID")

        existing_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not existing_post:
            raise HTTPException(status_code=404, detail="Post not found")

        update_data = post_update.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.utcnow()
        db.blog_posts.update_one({"_id": ObjectId(post_id)}, {"$set": update_data})

        updated_post = db.blog_posts.find_one({"_id": ObjectId(post_id)})
        return parse_json(updated_post)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blog_post(
    post_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Delete a blog post (admin/editor only)."""
    try:
        if current_user.role not in ["admin", "editor"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
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


@router.post("/posts/{post_id}/comments", response_model=Comment)
async def add_comment(
    post_id: str,
    comment: CommentCreate,
    current_user: Optional[User] = Depends(get_current_user),
):
    """Add a comment to a blog post."""
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
