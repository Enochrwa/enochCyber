# backend/app/core/security.py
import uuid # Added
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, AsyncGenerator
import os
from fastapi import HTTPException, status, Depends
from redis.asyncio import Redis as AsyncRedis # Added
from ..core.dependencies import get_redis_client # Added
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from ..database import get_db

# UserModel will be referred to as User as it's imported like that
from ..models.user import User

# UserInDB is not directly used in the functions being modified to return UserModel, so keeping it for now
from ..schemas.user import UserInDB

# TokenData will be imported from schemas.token by auth.py, remove local one if not used, or update.
# For now, the prompt doesn't explicitly say to remove it from here, but get_current_user will be changed to use scope.
# The prompt for get_current_user implies TokenData from schemas.token.py will be used.
# Let's remove the local definition to avoid conflict and assume it's resolved via auth.py's imports.
# from pydantic import BaseModel # BaseModel might still be needed if other Pydantic models are here. It's a common import.
from ..schemas.token import TokenData  # Explicitly import TokenData to be clear

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# The prompt mentions the tokenUrl for OAuth2PasswordBearer should be "auth/login/token"
# relative to the /api/v1 prefix. The current one is "api/auth/token".
# This will be: /api/v1/auth/login/token.
# If main app has /api/v1 prefix, then "auth/login/token" is correct.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login") # Corrected tokenUrl

SECRET_KEY = os.getenv("SECRET_KEY")
if SECRET_KEY is None:
    raise ValueError("Missing SECRET_KEY environment variable. Application cannot start without it.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Removed local TokenData class


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )  # Use constant
    jti = uuid.uuid4().hex # Generate a unique ID for the token
    to_encode.update({"exp": expire, "jti": jti}) # Add jti claim
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def add_token_to_blocklist(redis_client: AsyncRedis, jti: str, expires_at_timestamp: int):
    """Adds a token's JTI to the Redis blocklist with a TTL equal to the token's remaining validity."""
    now_timestamp = int(datetime.utcnow().timestamp())
    ttl = expires_at_timestamp - now_timestamp
    if ttl > 0:
        await redis_client.setex(f"blocked_jti:{jti}", ttl, "true")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    redis_client: AsyncRedis = Depends(get_redis_client) # Added redis_client
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")
        jti: Optional[str] = payload.get("jti")

        if username is None or jti is None: # JTI check added
            raise credentials_exception

        if await redis_client.exists(f"blocked_jti:{jti}"): # Blocklist check
            raise credentials_exception

        if scope == "2fa_required":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token valid only for 2FA verification step. Full authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token_data = TokenData(username=username, scope=scope)
    except JWTError:
        raise credentials_exception

    # Corrected the execute call
    result = await db.execute(select(User).where(User.username == token_data.username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user  # Return UserModel (which is User here)


async def get_current_active_user(
    current_user: User = Depends(get_current_user),  # Expect User (UserModel)
):
    if not current_user.is_active:  # is_active is on User model
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def authenticate_user(
    db: AsyncSession, username: str, password: str
) -> Optional[User]:  # Changed db_session to db
    # Use the passed db session directly
    result = await db.execute(
        select(User).where(User.username == username)
    )  # Changed db_session to db
    user = result.scalars().first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user  # Return the User model


async def get_current_user_for_2fa(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    redis_client: AsyncRedis = Depends(get_redis_client) # Added redis_client
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials for 2FA",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")
        user_id: Optional[int] = payload.get("user_id")
        jti: Optional[str] = payload.get("jti")

        if username is None or scope != "2fa_required" or user_id is None or jti is None: # JTI check added
            raise credentials_exception

        if await redis_client.exists(f"blocked_jti:{jti}"): # Blocklist check
            raise credentials_exception

        # token_data = TokenData(username=username, scope=scope) # Not strictly needed for user fetching here

    except JWTError:
        raise credentials_exception

    user = await db.get(User, user_id)
    if user is None or user.username != username:  # Verify username matches
        raise credentials_exception

    # Do not check for user.is_active here, as this token is only for 2FA step
    return user
