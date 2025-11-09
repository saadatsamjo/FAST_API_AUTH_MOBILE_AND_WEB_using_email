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


async def scheduled_token_cleanup():
    """Run one token cleanup cycle."""
    try:
        print(f"\n🔄 Starting token cleanup at {utcnow()}")
        async for db in get_db():
            await cleanup_expired_tokens(db)
        print(f"✅ Token cleanup completed at {utcnow()}")
    except Exception as e:
        print(f"❌ Token cleanup failed: {e}")


async def periodic_cleanup():
    """Run cleanup every 24 hours, delay first run slightly."""
    await asyncio.sleep(120)  # Give the DB a few seconds to settle and allow aut tables creation or migrations
    while True:
        await scheduled_token_cleanup()
        # run cleanup every 24 hours
        # await asyncio.sleep(60 * 60 * 24)

        # run cleanup every 10 Seconds
        await asyncio.sleep(10)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import app.model_registry  # ensure models are registered

    # Create tables only in development
    if settings.ENVIRONMENT == "development":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print(f"🚀 Tables auto-created ({settings.ENVIRONMENT} mode)")

    # Start background cleanup
    cleanup_task = asyncio.create_task(periodic_cleanup())
    print(f"✅ Background token cleanup started in {settings.ENVIRONMENT} mode")

    yield  # App runs here

    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await engine.dispose()
    print("👋 App shutdown complete")


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(user_settings_router, prefix="/api/settings", tags=["User Settings"])


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
