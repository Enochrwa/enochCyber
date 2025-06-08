# backend/app/api/admin.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession # Changed from sqlalchemy.orm import Session
from app.services.database.autofill import DatabaseAutofiller
from app.database import get_db
from ..models.user import User # Added
from ..core.security import get_current_active_user # Added
import asyncio # Added for to_thread if needed

router = APIRouter()


@router.post("/autofill/", tags=["Admin"]) # Added trailing slash
async def trigger_autofill(count: int = 10, db: AsyncSession = Depends(get_db), current_admin_user: User = Depends(get_current_active_user)):
    if not current_admin_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required")

    filler = DatabaseAutofiller(db)
    # Assuming DatabaseAutofiller.autofill_all is synchronous.
    # If it were async, it would be `results = await filler.autofill_all(count=count)`
    # For now, we'll call it directly. If it's blocking, it should be run in a thread pool.
    # For example: results = await asyncio.to_thread(filler.autofill_all, count=count)
    # This subtask specifies to make the endpoint async and call directly.
    results = filler.autofill_all(count=count) # This might need to be run in a threadpool if it's blocking
    return {"message": f"Added {len(results)} records", "details": results}
