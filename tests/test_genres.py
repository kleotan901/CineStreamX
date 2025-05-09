import logging

import pytest
from fastapi import HTTPException, status
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from config.dependencies import require_moderator
from database import UserModel, UserGroupModel, UserGroupEnum
from database.models.movies import GenreModel
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
async def test_get_genres_with_movies_count(
    db_session, seed_movie_certification, seed_genres
):
    """
    Test retrieving a list of genres with the count of associated movies.
    Steps:
    - Seeds the database with several movies belonging to different genres.
    - Sends a GET request to the /genres/ endpoint.
    - Verifies the response status code is 200.
    - Validates that the genres are returned in the expected order with the correct movie counts:
        - "Action" should have 3 movies.
        - "Comedy" should have 1 movie.
        - "Detective" should have 2 movies.
    """
    await create_movie_in_db(name="Movie 1", genres=["Detective"])
    await create_movie_in_db(name="Movie 2", genres=["Comedy", "Action"])
    await create_movie_in_db(name="Movie 3", genres=["Action"])
    await create_movie_in_db(name="Movie 4", genres=["Detective", "Action"])

    response = await async_client.get(f"{BASE_URL}genres/")
    assert response.status_code == 200
    response_data = response.json()

    assert response_data["genres"][0]["genre_name"] == "Action"
    assert (
        response_data["genres"][0]["movie_count"] == 3
    ), "Should be 3 films of Action genre"

    assert response_data["genres"][1]["genre_name"] == "Comedy"
    assert (
        response_data["genres"][1]["movie_count"] == 1
    ), "Should be 1 film of Comedy genre"

    assert response_data["genres"][2]["genre_name"] == "Detective"
    assert (
        response_data["genres"][2]["movie_count"] == 2
    ), "Should be 2 film of Detective genre"


@pytest.mark.asyncio
async def test_get_movies_of_each_genre(db_session, seed_movie_certification):
    """
    Test retrieving all movies associated with a specific genre by genre ID.
    Steps:
    - Create movies with different genre associations in the database.
    - Sends GET requests to the /movies-by-genre/{genre_id}/ endpoint.
    - Validates that the correct genre name and movie count are returned.
    - Verifies that the list of movies for each genre is accurate and ordered as expected:
        - Genre "Detective" (ID 1) should include Movie 1 and Movie 4.
        - Genre "Comedy" (ID 2) should include Movie 2, Movie 3, and Movie 4.
    """
    await create_movie_in_db(name="Movie 1", genres=["Detective"])
    await create_movie_in_db(name="Movie 2", genres=["Comedy"])
    await create_movie_in_db(name="Movie 3", genres=["Comedy"])
    await create_movie_in_db(name="Movie 4", genres=["Comedy", "Detective"])

    response_detective_genre = await async_client.get(f"{BASE_URL}movies-by-genre/1/")
    assert response_detective_genre.status_code == 200
    assert response_detective_genre.json()["genre_name"] == "Detective"
    assert response_detective_genre.json()["movie_count"] == 2
    assert response_detective_genre.json()["movies"][0]["name"] == "Movie 1"
    assert response_detective_genre.json()["movies"][1]["name"] == "Movie 4"

    response_comedy_genre = await async_client.get(f"{BASE_URL}movies-by-genre/2/")
    assert response_comedy_genre.json()["genre_name"] == "Comedy"
    assert response_comedy_genre.json()["movie_count"] == 3
    assert response_comedy_genre.json()["movies"][0]["name"] == "Movie 2"
    assert response_comedy_genre.json()["movies"][1]["name"] == "Movie 3"
    assert response_comedy_genre.json()["movies"][2]["name"] == "Movie 4"


# Test CRUD genres endpoints
@pytest.mark.asyncio
async def test_create_genre_by_unauthorized_user_not_authenticated_error(db_session):
    """
    Test that unauthorized user can not create a new genre.
    Raise an error - 'Not authenticated'.
    """
    payload = {"name": "Action"}
    response = await async_client.post(url=f"{BASE_URL}genres/", json=payload)
    assert response.json()["detail"] == "Not authenticated"
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_genre_by_moderator(db_session):
    """
        Test that a moderator can successfully create a new genre
        and that duplicate genre creation is properly handled.
    Steps:
    - create a user with the "MODERATOR" group.
    - generate an access token for the user.
    - send a POST request to create a new genre.
        Expect status code 201 and response to contain the correct genre name.
    - send another POST request with the same genre name.
       Expect status code 409 (Conflict) and error message indicating the genre already exists.
    Assertions:
        - The first request creates a genre successfully.
        - The second request fails with a conflict error.
    """
    # Override the dependency require_moderator
    app.dependency_overrides[require_moderator] = override_require_moderator

    # Send POST request
    payload = {"name": "Action"}
    response = await async_client.post(
        url=f"{BASE_URL}genres/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.status_code == 201

    stmt = select(GenreModel).where(GenreModel.id == 1)
    result = await db_session.execute(stmt)
    db_genre = result.scalars().first()
    assert db_genre.name == "Action"


    payload = {"name": "Action"}
    response = await async_client.post(
        url=f"{BASE_URL}genres/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "The genre 'Action' already exist in DB."


@pytest.mark.asyncio
async def test_update_genre_by_moderator(db_session, seed_genres):
    """
    Test that a moderator can edit successfully a genre.
    Steps:
        - override require_moderator function
        - send PUT request to /genres/3/ endpoint to update name of genre from 'Genre-2' to 'Comedy'
    """
    app.dependency_overrides[require_moderator] = override_require_moderator

    payload_update_genre = {"name": "Comedy"}
    response_update = await async_client.put(
        url=f"{BASE_URL}genres/3/",
        json=payload_update_genre,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response_update.json()["name"] == "Comedy"
    assert response_update.status_code == 200

    stmt_updated = select(GenreModel).where(GenreModel.id == 3)
    result = await db_session.execute(stmt_updated)
    updated_genre = result.scalars().first()
    assert updated_genre is not None, "Genre with ID 3 should exist"
    assert updated_genre.name == "Comedy", "The genre's name in DB should be changed from 'Genre-2' to 'Comedy'"


@pytest.mark.asyncio
async def test_delete_genre_by_moderator(db_session, seed_genres):
    """
    Test that a moderator can delete a genre.
    """
    app.dependency_overrides[require_moderator] = override_require_moderator

    response = await async_client.delete(
        url=f"{BASE_URL}genres/delete/5/",
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["message"] == "The genre 'Genre-4' was deleted!"
    assert response.status_code == 200

    stmt = select(GenreModel).where(GenreModel.name == "Genre-4")
    result = await db_session.execute(stmt)
    db_genre = result.scalars().first()
    assert db_genre is None


@pytest.mark.asyncio
async def test_create_genre_by_not_moderator_access_forbidden_error(db_session):
    """
    Test that a user can not create a new genre.
    Raises an error - 'Access forbidden: moderator only'.
    """
    # Step 2: Override the dependency
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    # Step 3: Send POST request
    payload = {"name": "Action"}
    response = await async_client.post(
        url=f"{BASE_URL}genres/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["detail"] == "Access forbidden: moderator only"
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_genre_by_not_moderator_access_forbidden_error(
    db_session, seed_genres
):
    """
    Test that a user can not edit a genre.
    Raises an error - 'Access forbidden: moderator only'.
    """
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    payload = {"name": "Action"}
    response = await async_client.put(
        url=f"{BASE_URL}genres/1/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"},
    )
    assert response.json()["detail"] == "Access forbidden: moderator only"
    assert response.status_code == 403, "The response status should be - 403 FORBIDDEN"

    stmt = select(GenreModel).where(GenreModel.id == 1)
    result = await db_session.execute(stmt)
    db_genre = result.scalars().first()
    assert db_genre.name != "Action", "The genre name has not been changed in DB"


@pytest.mark.asyncio
async def test_delete_genre_by_not_moderator_access_forbidden_error(
    db_session, seed_genres
):
    """
    Test that a user can not delete a genre.
    Raises an error - 'Access forbidden: moderator only'.
    """
    app.dependency_overrides[require_moderator] = (
        override_require_moderator_with_exception
    )

    response = await async_client.delete(
        url=f"{BASE_URL}genres/delete/1/",
        headers={"Authorization": "Bearer fake-token"},
    )
    assert (
        response.json()["detail"] == "Access forbidden: moderator only"
    ), "Should an error raises - 'Access forbidden: moderator only'"
    assert response.status_code == 403, "The response status should be - 403 FORBIDDEN"

    stmt = select(GenreModel).where(GenreModel.id == 1)
    result = await db_session.execute(stmt)
    db_genre = result.scalars().first()
    assert db_genre is not None, "The genre should still exist in DB"
