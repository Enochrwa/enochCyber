# backend/app/api/users.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from typing import List
from pydantic import BaseModel

from ..database import get_db
from ..models.user import User
from ..schemas.user import UserCreate, UserRead, UserUpdate # Changed UserInDB to UserRead
from ..services.user import get_user, get_users, create_user, update_user, delete_user, get_user_by_email
from ..core.security import get_current_active_user

router = APIRouter()


@router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED) # Changed UserInDB to UserRead
async def create_new_user(user: UserCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    db_user = await get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    return await create_user(db=db, user=user)


@router.get("/", response_model=List[UserRead]) # Changed UserInDB to UserRead
async def read_users(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    users = await get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=UserRead) # Changed UserInDB to UserRead
async def read_user(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        # Allow users to read their own data, or admins to read any user
        if current_user.id != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this user's data")

    db_user = await get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return db_user


@router.put("/{user_id}", response_model=UserRead) # Changed UserInDB to UserRead
async def update_existing_user(user_id: int, user: UserUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
         # Allow users to update their own data.
        if current_user.id != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this user")

    db_user = await get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return await update_user(db=db, user_id=user_id, user_update_schema=user)


@router.delete("/{user_id}", response_model=UserRead) # Changed UserInDB to UserRead
async def delete_existing_user(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    db_user = await get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return await delete_user(db=db, user_id=user_id)


# Pydantic model for User Summary
class UserSummary(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int


@router.get("/summary/", response_model=UserSummary) # Added trailing slash for consistency
async def get_user_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    """
    Retrieve a summary of users.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")

    total_users_stmt = select(func.count(User.id))
    admin_users_stmt = select(func.count(User.id)).where(User.is_superuser == True)

    total_users_result = await db.execute(total_users_stmt)
    total_users = total_users_result.scalar_one()

    admin_users_result = await db.execute(admin_users_stmt)
    admin_users = admin_users_result.scalar_one()

    standard_users = total_users - admin_users
    return UserSummary(total_users=total_users, admin_users=admin_users, standard_users=standard_users)
