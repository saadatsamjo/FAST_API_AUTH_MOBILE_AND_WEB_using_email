# app/authentication/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from app.database.connection import Base
from sqlalchemy.orm import relationship
from app.helpers.time import utcnow
from datetime import timedelta

# ✅ Token Blacklist
class ActiveToken(Base):
    __tablename__ = "active_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_type = Column(String, nullable=False)  # 'access' or 'refresh'
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    user = relationship("User")

#  ✅ Token Blacklist
class BlacklistedToken(Base):
    __tablename__ = "blacklisted_token"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    token_type = Column(String, nullable=False)  # 'access' or 'refresh' # i added this column
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False) 
    blacklisted_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    reason = Column(String, nullable=True)  # 'logout', 'password_change', 'account_deletion', 'token_expiration', 'revoked', 'password_reset'

    user = relationship("User", back_populates="blacklisted_tokens")


# ✅ Password Reset Token
class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), default=lambda: utcnow() + timedelta(hours=1))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    used = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="password_reset_tokens")