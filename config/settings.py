import os

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
SQLALCHEMY_DATABASE_URL = os.getenv(
    "SQLALCHEMY_DATABASE_URL", "sqlite+aiosqlite:///./movies_db.db"
)
