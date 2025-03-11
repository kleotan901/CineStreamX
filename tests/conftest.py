import pytest
import pytest_asyncio
from database import (
    SessionLocal,
    engine,
    reset_database,
    Base,
    get_sqlite_db_contextmanager,
)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_db(request):
    """
    Reset the SQLite database before each test function, except for tests marked with 'e2e'.

    By default, this fixture ensures that the database is cleared and recreated before every
    test function to maintain test isolation. However, if the test is marked with 'e2e',
    the database reset is skipped to allow preserving state between end-to-end tests.
    """
    if "e2e" in request.keywords:
        yield
    else:
        await reset_database()
        yield


@pytest_asyncio.fixture(scope="function")
def test_db():
    """Creates and drops the test database for each test."""
    Base.metadata.create_all(bind=engine)  # Create tables
    yield SessionLocal()  # Provide a session to tests
    Base.metadata.drop_all(bind=engine)  # Clean up after test


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Provide an async database session for database interactions.
    This fixture yields an async session using `get_db_contextmanager`, ensuring that the session
    is properly closed after each test.
    """
    async with get_sqlite_db_contextmanager() as session:
        yield session
