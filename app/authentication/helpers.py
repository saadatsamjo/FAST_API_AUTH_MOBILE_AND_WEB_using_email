# app/authentication/helpers.py

from fastapi import Header, HTTPException, status
from app.core.config import settings
from fastapi import Response
from typing import Literal
from enum import Enum

BASE_URL = settings.BASE_URL

# ✅ Formulate Reset Link
def formulate_reset_link(token: str):
    return f"{BASE_URL}/reset-password?token={token}"


# ✅ Client Type
class ClientType(str, Enum):
    WEB = "web"
    MOBILE = "mobile"


# ✅ Get  Type
def get_client_type(
    x_client_type: Literal["web", "mobile"] = Header(
        default="web",
        description="Client type: 'web' for browser (uses cookies) or 'mobile' for mobile apps (uses Authorization header)",
    )
) -> ClientType:
    """
    Dependency to determine client type from custom header.

    - web: Uses HTTP-only cookies for token storage
    - mobile: Uses Authorization Bearer tokens (stored in keychain/keystore)
    """
    try:
        return ClientType(x_client_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Client-Type header. Must be 'web' or 'mobile'",
        )

# ✅ Set Auth Cookies
def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """
    Set authentication cookies in the response.

    Args:
        response: FastAPI Response object
        access_token: JWT access token
        refresh_token: JWT refresh token
    """
    # Set access token cookie
    response.set_cookie(
        key=settings.ACCESS_TOKEN_COOKIE_NAME,
        value=access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRY * 60,  # Convert minutes to seconds
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
    )

    # Set refresh token cookie
    response.set_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRY * 24 * 60 * 60,  # Convert days to seconds
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
    )

# ✅ Clear Auth Cookies
def clear_auth_cookies(response: Response) -> None:
    """
    Clear authentication cookies from the response.

    Args:
        response: FastAPI Response object
    """
    # Delete access token cookie
    response.delete_cookie(
        key=settings.ACCESS_TOKEN_COOKIE_NAME,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )

    # Delete refresh token cookie
    response.delete_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )


# # ✅ Set Auth Response For Mobile
# def set_auth_response_for_mobile(access_token: str, refresh_token: str) -> dict:
#     """
#     Prepare token response for mobile clients (returns tokens in response body).
    
#     Args:
#         access_token: JWT access token
#         refresh_token: JWT refresh token
    
#     Returns:
#         Dictionary containing tokens to be stored in keychain/keystore
#     """
#     return {
#         "access_token": access_token,
#         "refresh_token": refresh_token,
#         "token_type": "bearer"
#     }