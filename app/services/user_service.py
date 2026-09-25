from fastapi import HTTPException, status
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash
from beanie import PydanticObjectId

class UserService:
    @staticmethod
    async def create_user(user_in: UserCreate, force_role: UserRole = None) -> User:
        user = await User.find_one({"email": user_in.email})
        if user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this email already exists."
            )
        
        # Determine role: usually student unless admin forces it
        role = force_role if force_role else UserRole.STUDENT
        
        new_user = User(
            email=user_in.email,
            hashed_password=get_password_hash(user_in.password),
            first_name=user_in.first_name,
            last_name=user_in.last_name,
            profile_image=user_in.profile_image,
            bio=user_in.bio,
            role=role
        )
        await new_user.insert()
        return new_user

    @staticmethod
    async def get_user_by_email(email: str) -> User:
        return await User.find_one({"email": email})

    @staticmethod
    async def get_user_by_id(user_id: PydanticObjectId) -> User:
        return await User.get(user_id)

    @staticmethod
    async def update_user(user: User, update_data: UserUpdate) -> User:
        update_dict = update_data.model_dump(exclude_unset=True)
        for field, value in update_dict.items():
            setattr(user, field, value)
        await user.save()
        return user
