# app/authentication/security.py

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from app.core.config import settings
from app.helpers.time import utcnow
from jose import JWTError, jwt
import secrets
import random

# Password hashing context
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


# ============================================================
# ✅ Verify Password
# ============================================================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

# ============================================================
# ✅ Get Password Hash
# ============================================================
def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)

# ============================================================
# ✅ Create Access Token
# ============================================================
async def create_access_token(
    data: Dict[str, Any], 
    db: AsyncSession,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token and store it as active."""
    to_encode = data.copy()

    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRY)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    # Store as active token
    from app.authentication.models import ActiveToken
    active_token = ActiveToken(
        token=encoded_jwt,
        user_id=data.get("user_id"),
        token_type="access",
        expires_at=expire
    )
    db.add(active_token)
    await db.commit()
    
    return encoded_jwt


# ============================================================
# ✅ Create Refresh Token
# ============================================================
async def create_refresh_token(
    data: Dict[str, Any], 
    db: AsyncSession,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT refresh token and store it as active."""
    to_encode = data.copy()

    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRY)

    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    # Store as active token
    from app.authentication.models import ActiveToken
    active_token = ActiveToken(
        token=encoded_jwt,
        user_id=data.get("user_id"),
        token_type="refresh",
        expires_at=expire
    )
    db.add(active_token)
    await db.commit()
    
    return encoded_jwt

# ============================================================
# ✅ Decode Token
# ============================================================
def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError:
        return None

# ============================================================
# ✅ Generate Password Reset Token
# ============================================================
def generate_password_reset_token() -> str:
    """Generate a secure random token for password reset."""
    return secrets.token_urlsafe(32)

# ============================================================
# ✅ Get Token Expiry
# ============================================================
def get_token_expiry(token_type: str = "access") -> datetime:
    """Get expiry datetime for a token."""
    if token_type == "refresh":
        return utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRY)
    return utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRY)

# ============================================================
# ✅ Generate Verification Code
# ============================================================
def generate_verification_code():
    """Generate a random 6-digit verification code."""
    return str(random.randint(100000, 999999))


# ============================================================
# ✅ Blacklist Access and Refresh Tokens on password change, logout, password reset, or account deletion
# ============================================================
async def blacklist_all_user_tokens(user_id: int, db: AsyncSession, reason: str = "security_event") -> None:
    """
    Blacklist ALL active tokens for a user.
    This effectively logs them out from all devices.
    """
    from app.authentication.models import ActiveToken, BlacklistedToken
    
    # 1. Get all active tokens for the user
    stmt = select(ActiveToken).where(
        and_(
            ActiveToken.user_id == user_id,
            ActiveToken.expires_at > utcnow()
        )
    )
    result = await db.execute(stmt)
    active_tokens = result.scalars().all()
    
    # 2. Blacklist each active token
    for active_token in active_tokens:
        blacklist_entry = BlacklistedToken(
            token=active_token.token,
            token_type=active_token.token_type,  # ADD THIS
            user_id=user_id,
            expires_at=active_token.expires_at,
            reason=reason
        )
        db.add(blacklist_entry)
        
        # 3. Remove from active tokens
        await db.delete(active_token)
    
    await db.commit()



# ============================================================
# ✅ Clean up expired tokens from active_tokens and blacklisted_token tables
# ============================================================  
async def cleanup_expired_tokens(db: AsyncSession) -> None:
    """Clean up expired tokens from active_tokens and  tables."""
    from app.authentication.models import ActiveToken, BlacklistedToken
    
    # Clean expired active tokens
    stmt = select(ActiveToken).where(ActiveToken.expires_at <= utcnow())
    result = await db.execute(stmt)
    expired_active = result.scalars().all()
    
    for token in expired_active:
        await db.delete(token)
    
    # Clean expired blacklisted tokens (optional)
    stmt = select(BlacklistedToken).where(BlacklistedToken.expires_at <= utcnow())
    result = await db.execute(stmt)
    expired_blacklisted = result.scalars().all()

    print(f'Expired | Blacklisted tokens cleaned: {len(expired_blacklisted)} | {utcnow()}')
    
    for token in expired_blacklisted:
        await db.delete(token)
    
    await db.commit()