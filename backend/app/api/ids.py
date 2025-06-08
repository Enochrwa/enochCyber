# backend/app/api/ids.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from ..database import get_db
from ..schemas.ids_rule import IDSRule, IDSRuleCreate, IDSRuleUpdate
from ..models.ids_rule import IDSRule as DBIDSRule
from ..models.user import User
from ..core.security import get_current_active_user

router = APIRouter()


@router.post("/", response_model=IDSRule, tags=["IDS"])
async def create_rule(rule: IDSRuleCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")
    db_rule = DBIDSRule(**rule.dict())
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.get("/", response_model=List[IDSRule], tags=["IDS"])
async def read_rules(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    result = await db.execute(select(DBIDSRule).offset(skip).limit(limit))
    return result.scalars().all()


@router.get("/{rule_id}", response_model=IDSRule, tags=["IDS"])
async def read_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    result = await db.execute(select(DBIDSRule).where(DBIDSRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=IDSRule, tags=["IDS"])
async def update_rule(rule_id: int, rule: IDSRuleUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")

    result = await db.execute(select(DBIDSRule).where(DBIDSRule.id == rule_id))
    db_rule = result.scalars().first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    update_data = rule.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_rule, field, value)

    await db.commit()
    await db.refresh(db_rule)
    return db_rule


@router.delete("/{rule_id}", tags=["IDS"])
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")

    result = await db.execute(select(DBIDSRule).where(DBIDSRule.id == rule_id))
    rule = result.scalars().first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    await db.delete(rule) # Changed from db.delete(rule)
    await db.commit()
    return {"message": "Rule deleted"}
