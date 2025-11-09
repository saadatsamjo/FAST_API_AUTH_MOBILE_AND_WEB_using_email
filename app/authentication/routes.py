# app/authentication/routes.py

from fastapi import (
    HTTPException,
    APIRouter,
    Response,
    Request,
    Depends,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Union

from app.database.connection import get_db
from app.users.schemas import UserRegister
from app.authentication.services import (
    create_password_reset_link,
    verify_email_with_code,
    refresh_access_token,
    resetting_password,
    update_password,
    register_user,
    login_user,
    logout_user,
)
from app.authentication.dependencies import (
    get_refresh_token_user,
    get_current_user,
)
from app.authentication.helpers import (
    # set_auth_response_for_mobile,
    clear_auth_cookies,
    set_auth_cookies,
    get_client_type,
    ClientType,
)
from app.users.models import User
from app.authentication.schemas import (
    TokenResponseAfterRegistrationMobile,
    TokenResponseAfterRegistrationWeb,
    TokenResponseAfterRefreshMobile,
    TokenResponseAfterLoginMobile,
    TokenResponseAfterRefreshWeb,
    TokenResponseAfterLoginWeb,
    AuthMessageResponse,
    ForgotPassword,
    ChangePassword,
    ResetPassword,
    VerifyEmail,
    UserLogin,
)
from app.core.config import settings

router = APIRouter()


# ============================================================
# ✅ REGISTER
# ============================================================
@router.post(
    "/register",
    response_model=Union[
        TokenResponseAfterRegistrationWeb, TokenResponseAfterRegistrationMobile
    ],
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegister,
    response: Response,
    client_type: ClientType = Depends(get_client_type),
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user.

    **Headers:**
    - `X-Client-Type`: `web` or `mobile` (default: `web`)

    **For Web Clients (X-Client-Type: web):**
    - Tokens are set as HTTP-only cookies
    - Response contains only user info

    **For Mobile Clients (X-Client-Type: mobile):**
    - Tokens are returned in response body
    - Store tokens in secure storage (Keychain/Keystore)
    """
    user_response = await register_user(user_data, db)

    if client_type == ClientType.WEB:
        set_auth_cookies(
            response, user_response.access_token, user_response.refresh_token
        )
        return TokenResponseAfterRegistrationWeb(
            user=user_response.user, message="Registration successful"
        )

    return TokenResponseAfterRegistrationMobile(
        user=user_response.user,
        access_token=user_response.access_token,
        refresh_token=user_response.refresh_token,
        message="Registration successful",
    )


# ============================================================
# ✅ LOGIN
# ============================================================
@router.post(
    "/login",
    response_model=Union[TokenResponseAfterLoginWeb, TokenResponseAfterLoginMobile],
    status_code=status.HTTP_200_OK,
)
async def login(
    user_data: UserLogin,
    response: Response,
    client_type: ClientType = Depends(get_client_type),
    db: AsyncSession = Depends(get_db),
):
    """
    Login user.

    **Headers:**
    - `X-Client-Type`: `web` or `mobile` (default: `web`)

    **For Web Clients (X-Client-Type: web):**
    - Tokens are set as HTTP-only cookies
    - Subsequent requests automatically include cookies

    **For Mobile Clients (X-Client-Type: mobile):**
    - Tokens are returned in response body
    - Include `Authorization: Bearer <access_token>` in subsequent requests
    - Store tokens securely in Keychain (iOS) or Keystore (Android)
    """
    access_token, refresh_token = await login_user(user_data, db)

    if client_type == ClientType.WEB:
        set_auth_cookies(response, access_token, refresh_token)
        return TokenResponseAfterLoginWeb(message="Login successful")

    return TokenResponseAfterLoginMobile(
        access_token=access_token,
        refresh_token=refresh_token,
        message="Login successful",
    )


# ============================================================
# ✅ REFRESH TOKENS
# ============================================================
@router.post(
    "/refresh",
    response_model=Union[TokenResponseAfterRefreshWeb, TokenResponseAfterRefreshMobile],
    status_code=status.HTTP_200_OK,
)
async def refresh_token(
    response: Response,
    client_type: ClientType = Depends(get_client_type),
    user_and_token: tuple = Depends(get_refresh_token_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access and refresh tokens.

    **Headers:**
    - `X-Client-Type`: `web` or `mobile` (default: `web`)

    **For Web Clients (X-Client-Type: web):**
    - Refresh token is read from cookies
    - New tokens are set as HTTP-only cookies

    **For Mobile Clients (X-Client-Type: mobile):**
    - Send refresh token in `Authorization: Bearer <refresh_token>` header
    - New tokens are returned in response body
    - Update stored tokens in Keychain/Keystore

    The old refresh token will be blacklisted.
    """
    user, refresh_token = user_and_token

    new_access_token, new_refresh_token = await refresh_access_token(refresh_token, db)

    if client_type == ClientType.WEB:
        set_auth_cookies(response, new_access_token, new_refresh_token)
        return TokenResponseAfterRefreshWeb(message="Tokens refreshed successfully")

    return TokenResponseAfterRefreshMobile(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        message="Tokens refreshed successfully",
    )


# ============================================================
# ✅ LOGOUT
# ============================================================
@router.post(
    "/logout",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def logout(
    request: Request,
    response: Response,
    client_type: ClientType = Depends(get_client_type),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout the current user.

    **Headers:**
    - `X-Client-Type`: `web` or `mobile` (default: `web`)

    **For Web Clients:**
    - Clears authentication cookies

    **For Mobile Clients:**
    - Blacklists the current access token
    """
    token = None

    if client_type == ClientType.WEB:
        token = request.cookies.get(settings.ACCESS_TOKEN_COOKIE_NAME)
        clear_auth_cookies(response)
    else:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No token provided for logout",
        )

    await logout_user(token, user, db)
    return AuthMessageResponse(message="Successfully logged out")


# ============================================================
# ✅ FORGOT PASSWORD
# ============================================================
@router.post(
    "/forgot-password",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def forgot_password(payload: ForgotPassword, db: AsyncSession = Depends(get_db)):
    """
    Request a password reset email.
    """
    await create_password_reset_link(payload.email, db)
    return {"message": "If the email exists, a password reset link has been sent."}


# ============================================================
# ✅ RESET PASSWORD
# ============================================================
@router.post(
    "/reset-password",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def reset_password(payload: ResetPassword, db: AsyncSession = Depends(get_db)):
    """
    Reset user password using reset token.
    """
    await resetting_password(payload.token, payload.new_password, db)
    return {"message": "Password has been reset successfully"}


# ============================================================
# ✅ CHANGE PASSWORD
# ============================================================
@router.post(
    "/change-password",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def change_password(
    payload: ChangePassword,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Change user password while logged in.
    """
    await update_password(user, payload.current_password, payload.new_password, db)
    return {"message": "Password updated successfully"}


# ============================================================
# ✅ VERIFY EMAIL
# ============================================================
@router.post(
    "/verify-email",
    response_model=AuthMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_email(
    payload: VerifyEmail,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify a user's email with the provided verification code.
    """
    await verify_email_with_code(user, payload.verification_code, db)
    return {"message": "Email verified successfully"}
