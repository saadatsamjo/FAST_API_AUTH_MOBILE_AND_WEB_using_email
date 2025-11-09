# app/main.py

from app.user_settings.routes import router as user_settings_router
from app.authentication.routes import router as auth_router
from app.authentication.security import cleanup_expired_tokens
from app.database.connection import get_db, engine, Base
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.config import settings
from app.helpers.time import utcnow
from fastapi import FastAPI
import uvicorn
import asyncio


# scheduling token cleanup task which will use async for loop to clean up expired tokens
async def scheduled_token_cleanup():
    """Background task to clean up expired tokens using async for loop"""
    try:
        print(f"\n🔄 Starting token cleanup at {utcnow()}")
        async for db in get_db():
            await cleanup_expired_tokens(db)
        print(f"✅ Token cleanup completed at {utcnow()}")
    except Exception as e:
        print(f"❌ Token cleanup failed: {e}")

async def periodic_cleanup():
    """Run cleanup every 24 hours"""
    while True:
        await scheduled_token_cleanup()
        # Wait 10 minutes
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles app startup and shutdown.
    """
    # ✅ Startup logic
    import app.model_registry  # ensures models are registered

    # Start background cleanup task using asyncio.create_task (fastapi internal scheduler)
    cleanup_task = asyncio.create_task(periodic_cleanup())
    print("✅ Background token cleanup started (runs every 24 hours)\n")

    # FOR DEVELOPMENT - Uncomment to create tables on startup
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)
    # print("🚀 App startup complete")

    yield  # Application runs here

    # ✅ Shutdown logic
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await engine.dispose()
    print("👋 App shutdown complete")


# Initialize FastAPI with the lifespan handler
app = FastAPI(lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],  # The specific frontend URL allowed
    # allow_origins=[settings.FRONTEND_URL, "http://127.0.0.1:3000"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(user_settings_router, prefix="/api/settings", tags=["User Settings"])



if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)