import logging

import pytest
from fastapi import HTTPException, status
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from config.dependencies import require_moderator
from database import UserModel, UserGroupModel, UserGroupEnum
from database.models.movies import GenreModel, StarModel
from main import app
from tests.test_movies import create_movie_in_db

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000/api/v1/theater/"
async_client = AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL)


# Override require_moderator dependency to create Fake moderator
async def override_require_moderator():
    return UserGroupModel(id=1, name=UserGroupEnum.MODERATOR)


# Override require_moderator dependency that raises the exception
async def override_require_moderator_with_exception():
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access forbidden: moderator only",
    )


@pytest.mark.asyncio
async def test_get_stars_list(
    db_session, seed_stars
):
    """
    Test retrieving a list of stars.
    Steps:
    - Sends a GET request to the /stars/ endpoint.
    - Verifies the response status code is 200.
    - Verifies the total number of stars in the response.
    """

    response = await async_client.get(f"{BASE_URL}stars/")
    assert response.status_code == 200, "Should be response status code - 200 OK"
    response_data = response.json()

    assert len(response_data["stars"]) == 10, "Should be 10 records in the 'stars' table in DB"


# Test CRUD stars endpoints
@pytest.mark.asyncio
async def test_create_star_by_unauthorized_user_not_authenticated_error(db_session):
    """
    Test that unauthorized user can not create a new star.
    Raise an error - 'Not authenticated'.
    """
    payload = {"name": "John Smith"}
    response = await async_client.post(url=f"{BASE_URL}stars/", json=payload)
    assert response.json()["detail"] == "Not authenticated"
    assert response.status_code == 401 ,"Should be response status - 401 NOT AUTHENTICATED"


@pytest.mark.asyncio
async def test_create_star_by_moderator(db_session):
    """
        Test that a moderator can successfully create a new star
        and that duplicate of star creation is properly handled.
    Steps:
    - create a user with the "MODERATOR" group.
    - generate an access token for the user.
    - send a POST request to create a new star.
        Expect status code 201 and response to contain the correct actor's name.
    - send another POST request with the same actor's name.
       Expect status code 409 (Conflict) and error message indicating the star already exists.
    Assertions:
        - The first request creates a star successfully.
        - The second request fails with a conflict error.
    """
    # Override the dependency require_moderator
    app.dependency_overrides[require_moderator] = override_require_moderator

    # Send POST request
    payload = {"name": "John Smith"}
    response = await async_client.post(
        url=f"{BASE_URL}stars/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.status_code == 201

    stmt = select(StarModel).where(StarModel.id == 1)
    result = await db_session.execute(stmt)
    db_genre = result.scalars().first()
    assert db_genre.name == "John Smith"


    payload = {"name": "John Smith"}
    response = await async_client.post(
        url=f"{BASE_URL}stars/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "The star with name - 'John Smith' already exists in DB."


@pytest.mark.asyncio
async def test_update_star_by_moderator(db_session, seed_stars):
    """
    Test that a moderator can edit successfully a star's data.
    Steps:
        - override require_moderator function
        - send PUT request to /stars/3/ endpoint to update name of star from 'Actor-3' to 'John Smith'
    """
    app.dependency_overrides[require_moderator] = override_require_moderator

    payload_update_genre = {"name": "John Smith"}
    response_update = await async_client.put(
        url=f"{BASE_URL}stars/3/",
        json=payload_update_genre,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response_update.json()["name"] == "John Smith"
    assert response_update.status_code == 200

    stmt_updated = select(StarModel).where(StarModel.id == 3)
    result = await db_session.execute(stmt_updated)
    updated_star = result.scalars().first()
    assert updated_star is not None, "Actor with ID 3 should exists"
    assert updated_star.name == "John Smith", "The actor's name in DB should be changed from 'Actor-2' to 'John Smith'"


@pytest.mark.asyncio
async def test_delete_star_by_moderator(db_session, seed_stars):
    """
    Test that a moderator can delete a star.
    """
    app.dependency_overrides[require_moderator] = override_require_moderator

    response = await async_client.delete(
        url=f"{BASE_URL}stars/delete/5/",
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["message"] == "The star 'Actor-4' was deleted!"
    assert response.status_code == 200

    stmt = select(StarModel).where(StarModel.name == "Actor-4")
    result = await db_session.execute(stmt)
    db_star = result.scalars().first()
    assert db_star is None


@pytest.mark.asyncio
async def test_create_star_by_not_moderator_access_forbidden_error(db_session):
    """
    Test that a user can not create a new star.
    Raises an error - 'Access forbidden: moderator only'.
    """
    # Step 2: Override the dependency
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    # Step 3: Send POST request
    payload = {"name": "John Smith"}
    response = await async_client.post(
        url=f"{BASE_URL}stars/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["detail"] == "Access forbidden: moderator only"
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_star_by_not_moderator_access_forbidden_error(
    db_session, seed_stars
):
    """
    Test that a user can not edit a star.
    Raises an error - 'Access forbidden: moderator only'.
    """
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    payload = {"name": "John Smith"}
    response = await async_client.put(
        url=f"{BASE_URL}stars/1/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["detail"] == "Access forbidden: moderator only"
    assert response.status_code == 403, "The response status should be - 403 FORBIDDEN"

    stmt = select(StarModel).where(StarModel.id == 1)
    result = await db_session.execute(stmt)
    db_star = result.scalars().first()
    assert db_star.name != "John Smith", "The actor's name has not been changed in DB"
    assert db_star.name == "Actor-0", "The actor's name in DB - 'Actor-0"


@pytest.mark.asyncio
async def test_delete_star_by_not_moderator_access_forbidden_error(
    db_session, seed_stars
):
    """
    Test that a user can not delete a star.
    Raises an error - 'Access forbidden: moderator only'.
    """
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    response = await async_client.delete(
        url=f"{BASE_URL}stars/delete/1/",
        headers={"Authorization": "Bearer fake-token"},
    )
    assert (
        response.json()["detail"] == "Access forbidden: moderator only"
    ), "Should an error raises - 'Access forbidden: moderator only'"
    assert response.status_code == 403, "The response status should be - 403 FORBIDDEN"

    stmt = select(StarModel).where(StarModel.id == 1)
    result = await db_session.execute(stmt)
    db_star = result.scalars().first()
    assert db_star is not None, "The star should still exists in DB"
