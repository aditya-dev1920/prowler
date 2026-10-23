"""
MongoDB Connection Manager for Prowler IASM.
Provides connection pooling, lifecycle management, ping checks, and graceful fallback.
"""

import logging
import os
import sys
from typing import Any, Optional

logger = logging.getLogger("prowler_iasm_db")
if not logger.handlers and not logging.getLogger().handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# Optional async and sync driver imports with graceful fallback
try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
except ImportError:
    AsyncIOMotorClient = None
    AsyncIOMotorDatabase = None

try:
    from pymongo import MongoClient
    from pymongo.database import Database
except ImportError:
    MongoClient = None
    Database = None


class MongoManager:
    """
    Singleton connection manager handling AsyncIOMotorClient for FastAPI
    and standard sync MongoClient for background workers and CLI tasks.
    """

    def __init__(self):
        self.async_client: Optional[Any] = None
        self.async_db: Optional[Any] = None
        self.sync_client: Optional[Any] = None
        self.sync_db: Optional[Any] = None
        self._connected: bool = False

    @property
    def uri(self) -> str:
        return os.getenv("MONGO_URI", "mongodb://localhost:27017")

    @property
    def db_name(self) -> str:
        return os.getenv("MONGO_DB_NAME", "prowler_iasm")

    @property
    def timeout_ms(self) -> int:
        return int(os.getenv("MONGO_TIMEOUT_MS", "2000"))

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        """
        Initializes the async connection pool and validates connection with a ping.
        Fails fast within timeout_ms and gracefully degrades if MongoDB is unavailable.
        """
        if AsyncIOMotorClient is None:
            logger.warning("[MongoDB] 'motor' package not installed. Running in flat-file fallback mode.")
            self._connected = False
            return False

        try:
            logger.info(f"[MongoDB] Initializing async connection pool to {self.uri}/{self.db_name}...")
            self.async_client = AsyncIOMotorClient(
                self.uri,
                maxPoolSize=50,
                minPoolSize=5,
                maxIdleTimeMS=45000,
                serverSelectionTimeoutMS=self.timeout_ms,
                connectTimeoutMS=self.timeout_ms,
                socketTimeoutMS=10000,
            )
            self.async_db = self.async_client[self.db_name]

            # Health ping check to verify connectivity
            await self.async_db.command("ping")
            self._connected = True
            logger.info(f"[MongoDB] Successfully connected to database '{self.db_name}'.")
            return True
        except Exception as e:
            self._connected = False
            logger.warning(
                f"[MongoDB] Unable to connect to MongoDB ({e}). "
                f"Operating in flat-file fallback mode (zero downtime)."
            )
            return False

    def get_sync_database(self) -> Optional[Any]:
        """
        Returns a connected synchronous Database client for scripts like post_processor.py.
        """
        if MongoClient is None:
            logger.warning("[MongoDB] 'pymongo' package not installed.")
            return None

        if self.sync_db is not None:
            return self.sync_db

        try:
            self.sync_client = MongoClient(
                self.uri,
                maxPoolSize=20,
                minPoolSize=2,
                serverSelectionTimeoutMS=self.timeout_ms,
                connectTimeoutMS=self.timeout_ms,
                socketTimeoutMS=10000,
            )
            self.sync_db = self.sync_client[self.db_name]
            self.sync_db.command("ping")
            return self.sync_db
        except Exception as e:
            logger.warning(f"[MongoDB-Sync] Connection failed: {e}")
            return None

    async def disconnect(self):
        """Cleanly drains and closes connection pools."""
        if self.async_client:
            logger.info("[MongoDB] Closing async connection pool...")
            self.async_client.close()
            self.async_client = None
            self.async_db = None

        if self.sync_client:
            logger.info("[MongoDB] Closing sync connection pool...")
            self.sync_client.close()
            self.sync_client = None
            self.sync_db = None

        self._connected = False


# Global singleton instance
mongo_manager = MongoManager()


async def connect_to_mongo() -> bool:
    return await mongo_manager.connect()


async def close_mongo_connection():
    await mongo_manager.disconnect()


def get_async_db() -> Optional[Any]:
    return mongo_manager.async_db


def get_sync_db() -> Optional[Any]:
    return mongo_manager.get_sync_database()


def is_mongo_connected() -> bool:
    return mongo_manager.is_connected

