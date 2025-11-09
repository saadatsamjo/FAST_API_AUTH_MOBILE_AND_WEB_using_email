# app/authentication/schemas.py

from pydantic import BaseModel, EmailStr, Field
from app.users.schemas import UserResponse
from typing import Optional

# ============================================================
# ✅ Auth-related input schemas
# ============================================================
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    # token: str  # ADD THIS LINE 
    new_password: str = Field(..., min_length=8, max_length=100)

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)

class VerifyEmail(BaseModel):
    verification_code: str

# ============================================================
# ✅ Auth-related response schemas
# ============================================================
# ✅ For WEB clients (cookies)
class TokenResponseAfterRegistrationWeb(BaseModel):
    """Response after registration for web clients - tokens are set in cookies"""
    user: UserResponse
    message: str = "Registration successful"

class TokenResponseAfterLoginWeb(BaseModel):
    """Response after login for web clients - tokens are set in cookies"""
    message: str = "Login successful"

class TokenResponseAfterRefreshWeb(BaseModel):
    """Response after token refresh for web clients - tokens are set in cookies"""
    message: str = "Tokens refreshed successfully"

# ✅ For MOBILE clients (tokens in response body)
class TokenResponseAfterRegistrationMobile(BaseModel):
    """Response after registration for mobile clients - tokens in body for keychain/keystore"""
    user: UserResponse
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    message: str = "Registration successful"

class TokenResponseAfterLoginMobile(BaseModel):
    """Response after login for mobile clients - tokens in body for keychain/keystore"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    message: str = "Login successful"

class TokenResponseAfterRefreshMobile(BaseModel):
    """Response after token refresh for mobile clients - tokens in body for keychain/keystore"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    message: str = "Tokens refreshed successfully"

# ============================================================
# ✅ Generic message response
# ============================================================
class AuthMessageResponse(BaseModel):
    message: str