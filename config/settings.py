import os

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
SQLALCHEMY_DATABASE_URL = os.getenv(
    "SQLALCHEMY_DATABASE_URL", "sqlite+aiosqlite:///./movies_db.db"
)

BASE_URL = "http://127.0.0.1:8000/api/v1/"
CELERY_BROKER_URL = "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = "redis://localhost:6379/0"
