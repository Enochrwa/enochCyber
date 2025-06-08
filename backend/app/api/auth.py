# backend/app/api/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from fastapi_limiter.depends import RateLimiter # Added
import pyotp  # Added
from sqlalchemy.ext.asyncio import AsyncSession  # Added

from ..core.security import (
    authenticate_user,
    create_access_token,
    get_current_active_user,  # Will be replaced by get_current_user_for_2fa for one endpoint
    get_current_user_for_2fa,  # Added
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from ..schemas.user import UserRead # Changed UserInDB to UserRead
from ..schemas.token import Token
from ..schemas.auth import TwoFactorVerify
from ..database import get_db
from ..models.user import User
from ..core.security import add_token_to_blocklist, oauth2_scheme, SECRET_KEY, ALGORITHM # Added
from ..core.dependencies import get_redis_client # Added
from redis.asyncio import Redis as AsyncRedis # Added
from jose import jwt, JWTError # Added

router = APIRouter()


@router.post(
    "/login",
    dependencies=[Depends(RateLimiter(times=5, seconds=60))] # Added RateLimiter
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    user = await authenticate_user(
        db, form_data.username, form_data.password
    )  # Added db
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.is_two_factor_enabled:
        access_token_expires = timedelta(minutes=5)  # Short expiry for 2FA token
        access_token = create_access_token(
            data={"sub": user.username, "scope": "2fa_required", "user_id": user.id},
            expires_delta=access_token_expires,
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "is_2fa_required": True,
            "user_id": user.id,
        }
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},  # No "2fa_required" scope
            expires_delta=access_token_expires,
        )
        return {"access_token": access_token, "token_type": "bearer"}


@router.post(
    "/verify-2fa",
    response_model=Token,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))] # Added RateLimiter
)
async def verify_2fa_login(
    request_data: TwoFactorVerify,
    current_user: User = Depends(get_current_user_for_2fa),
    db: AsyncSession = Depends(get_db),
):
    # current_user here is the user object fetched based on the temporary 2FA token.
    # The get_current_user_for_2fa dependency will ensure the token had the '2fa_required' scope.

    user = await db.get(User, current_user.id)  # Fetch the full User model instance
    if not user or not user.is_two_factor_enabled or not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled or user not found.",
        )

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(request_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If code is valid, issue a new token without 2FA scope
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires  # Regular scope
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserRead) # Changed from UserInDB
async def read_users_me(
    current_user: User = Depends(get_current_active_user) # current_user is SQLAlchemy User model
):
    return current_user # FastAPI will map User SQLAlchemy model to UserRead Pydantic model


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
    token: str = Depends(oauth2_scheme),
    redis_client: AsyncRedis = Depends(get_redis_client)
):
    try:
        # Decode the token to get jti and exp without verifying expiry,
        # as we want to blocklist even an expired token's jti if logout is attempted.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        jti = payload.get("jti")
        exp_timestamp = payload.get("exp") # This is a Unix timestamp

        if jti and exp_timestamp:
            await add_token_to_blocklist(redis_client, jti, int(exp_timestamp))

        return {"message": "Successfully logged out"}
    except JWTError:
        # Token is already invalid (e.g., malformed, wrong signature)
        # User is effectively logged out.
        return {"message": "Logout successful (token was invalid)"}
    except Exception as e:
        # Log this error on the server side for investigation
        # logger.error(f"Error during logout token blocklisting: {e}") # Assuming logger is available
        # Still return a success-like message to the client as logout shouldn't ideally fail from user's perspective
        return {"message": "Logout processed with an internal finalization error"}
