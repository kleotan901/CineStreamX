import logging
from wsgiref.validate import assert_

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func

from database.models.movies import (
    CertificationModel,
    GenreModel,
    StarModel,
    DirectorModel,
    MovieModel,
)
from main import app

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000/api/v1/theater/"
async_client = AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL)


@pytest.mark.asyncio
async def create_movie_in_db(
    name: str = "The TestMovie",
    year: int = 2008,
    time: int = 150,
    imdb: float = 9,
    description: str = "Some test description",
    db_certification_id: int = 1,
    genres: list[str] = ["Crime", "Adventure"],
    stars: list[str] = ["John Doe", "Mike Doe"],
    directors: list[str] = ["Christopher Nolan"],
):
    payload = {
        "name": name,
        "year": year,
        "time": time,
        "imdb": imdb,
        "votes": 3000000,
        "meta_score": 84,
        "gross": 1006000000,
        "description": description,
        "price": 104.00,
        "certification_id": db_certification_id,
        "genres": genres,
        "stars": stars,
        "directors": directors,
    }
    response = await async_client.post(f"{BASE_URL}movies/", json=payload)
    return response


@pytest.mark.asyncio
async def test_get_movies_with_pagination(
    db_session, seed_genres, seed_stars, seed_directors, seed_movies
):
    """
    Test case for retrieving list of movies with pagination.
    """
    count_stmt = select(func.count(MovieModel.id))
    result_count = await db_session.execute(count_stmt)
    total_items = result_count.scalar()
    assert total_items == 29

    movie_stmt = select(MovieModel).where(MovieModel.id == 15)
    result = await db_session.execute(movie_stmt)
    db_movie = result.scalars().first()
    assert db_movie.name == "TestMovie - 15"

    response = await async_client.get(f"{BASE_URL}movies/?page=2&per_page=4")

    response_data = response.json()
    assert response_data["prev_page"] == "/theater/movies/?page=1&per_page=4"
    assert response_data["next_page"] == "/theater/movies/?page=3&per_page=4"


@pytest.mark.asyncio
async def test_get_movies_filtered_by_year(
    db_session,
    seed_genres,
    seed_stars,
    seed_directors,
    seed_movies,
    seed_movie_certification,
):
    """
    Test case for get movies filtering by year.
    """
    await create_movie_in_db(name="TestName1", year=2007)
    await create_movie_in_db(name="TestName2", year=2007)
    await create_movie_in_db(name="TestName3 (2024)", year=2024)

    response = await async_client.get(f"{BASE_URL}movies/?year=2007&page=1&per_page=10")
    response_data = response.json()
    assert response_data["total_items"] == 32, "Should be 32 movies in DB"
    assert len(response_data["movies"]) == 2, "Should be 2 movies of 2007 year"
    assert response_data["movies"][0]["year"] == 2007
    assert response_data["movies"][1]["year"] == 2007


@pytest.mark.asyncio
async def test_get_movies_filtered_by_imdb(db_session, seed_movie_certification):
    """
    Test case for get movies filtering by imdb.
    """
    await create_movie_in_db(name="TestName1", imdb=5.6)
    await create_movie_in_db(name="TestName2", imdb=6.7)
    await create_movie_in_db(name="TestName3 (imdb)", imdb=4.2)

    response = await async_client.get(f"{BASE_URL}movies/?imdb=5.2&page=1&per_page=10")
    response_data = response.json()
    assert response_data["total_items"] == 3, "Should be 3 movies in DB"
    assert (
        len(response_data["movies"]) == 2
    ), "Should be 2 movies with imdb greater than 5.2"
    assert response_data["movies"][0]["imdb"] == 5.6
    assert response_data["movies"][1]["imdb"] == 6.7


@pytest.mark.asyncio
async def test_get_movies_filtered_by_genre(db_session, seed_movie_certification):
    """
    Test case for get movies filtering by genre.
    """
    await create_movie_in_db(name="TestName1", genres=["Crime", "Action"])
    await create_movie_in_db(name="TestName2", genres=["Crime", "Comedy"])
    await create_movie_in_db(name="TestName3", genres=["Comedy"])
    await create_movie_in_db(name="TestName4", genres=["Comedy"])

    response = await async_client.get(
        f"{BASE_URL}movies/?filter_by_genre=comedy&page=1&per_page=10"
    )
    response_data = response.json()
    assert response_data["total_items"] == 4, "Should be 4 movies in DB"
    assert len(response_data["movies"]) == 3, "Should be 3 movies with Comedy genre"

    response = await async_client.get(
        f"{BASE_URL}movies/?filter_by_genre=action&page=1&per_page=10"
    )
    assert len(response.json()["movies"]) == 1, "Should be 1 movie with Action genre"


@pytest.mark.asyncio
async def test_search_movies_by_star(db_session, seed_movie_certification):
    """
    Test case for searching movies by star name.
    """
    await create_movie_in_db(name="TestName1", stars=["John Doe", "Linda Bore"])
    await create_movie_in_db(name="TestName2", stars=["Mike Doe"])
    await create_movie_in_db(name="TestName3", stars=["Molly Flake", "Lu Dzy"])

    response = await async_client.get(f"{BASE_URL}movies/?search_by_star=Doe")
    response_data = response.json()
    assert response_data["total_items"] == 3, "Should be 3 movies in DB"
    assert len(response_data["movies"]) == 2, (
        "With searching by the actor name - 'Dou' "
        "should be found 2 movies with stars: John Doe and Mike Doe"
    )


@pytest.mark.asyncio
async def test_search_movies_by_director(db_session, seed_movie_certification):
    """
    Test case for searching movies by director name.
    """
    await create_movie_in_db(name="TestName1", directors=["John Smith"])
    await create_movie_in_db(name="TestName2", directors=["Mike Smith", "Molly Flake"])
    await create_movie_in_db(name="TestName3", directors=["Molly Flake", "Lu Dzy"])

    response = await async_client.get(
        f"{BASE_URL}movies/?search_by_director=Mike%20Smith"
    )
    response_data = response.json()
    assert response_data["total_items"] == 3, "Should be 3 movies in DB"
    assert len(response_data["movies"]) == 1, (
        "With searching by the director name - 'Mike Smith' "
        "should be found 1 movie with directed by Mike Smith"
    )


@pytest.mark.asyncio
async def test_search_movies_by_name_or_description(
    db_session, seed_movie_certification
):
    """
    Test case for searching movies by movie's name or description.
    """
    await create_movie_in_db(
        name="The Dark Knight 3",
        description="When a menace known as the Joker wreaks havoc and chaos on the ",
    )
    await create_movie_in_db(name="The Dark Knight 2", description="some description")
    await create_movie_in_db(name="Test Movie")

    response = await async_client.get(
        f"{BASE_URL}movies/?search_by_name_or_description=The%20Dark"
    )
    response_data = response.json()
    assert response_data["total_items"] == 3, "Should be 3 movies in DB"
    assert len(response_data["movies"]) == 2, (
        "With searching by the movie's name - 'The Dark' "
        "should be found 2 movies with names 'The Dark Knight 2' and 'The Dark Knight 3'"
    )

    response = await async_client.get(
        f"{BASE_URL}movies/?search_by_name_or_description=joker"
    )
    assert len(response.json()["movies"]) == 1, (
        "With searching by the search query - '?search_by_name_or_description=joker' "
        "should be found 1 movie with name 'The Dark Knight 3'"
    )


@pytest.mark.asyncio
async def test_create_movie_success(db_session, seed_movie_certification):
    """
    Test case for successfully creating a movie.
    This test ensures that when a new movie is created:
    - The provided data is correctly stored in the database.
    - New genres, stars, and directors are added to their respective tables if they do not already exist.

    Test Steps:
    1. Verify that the `GenreModel`, `StarModel`, and `DirectorModel` tables are initially empty.
    2. Send a POST request to create a new movie with associated genres, stars, and directors.
    3. Confirm that the API returns a `201` status code along with a success message.
    4. Query the database to validate that:
       - The movie record has been created in `MovieModel`.
       - The specified genres, stars, and directors have been added to their respective tables.

    Expected Outcome:
    - The movie is successfully created with all input data.
    - New genres, stars, and directors are added if they were not previously present in the database.
    """
    genres_stmt = select(GenreModel)
    result = await db_session.execute(genres_stmt)
    db_genres = result.scalars().all()
    assert (
        db_genres == []
    ), "The genre table should be empty before the request of movie creation"

    stars_stmt = select(StarModel)
    result = await db_session.execute(stars_stmt)
    db_stars = result.scalars().all()
    assert (
        db_stars == []
    ), "The stars table should be empty before the request of movie creation"

    directors_stmt = select(DirectorModel)
    result = await db_session.execute(directors_stmt)
    db_directors = result.scalars().all()
    assert (
        db_directors == []
    ), "The directors table should be empty before the request of movie creation"

    response = await create_movie_in_db()
    response_data = response.json()
    assert response.status_code == 201
    assert response_data["message"] == "Movie was created successfully!"

    movie_stmt = select(MovieModel).where(MovieModel.id == 1)
    result = await db_session.execute(movie_stmt)
    db_movie = result.scalars().first()
    assert db_movie.name == "The TestMovie"

    genres_stmt = select(GenreModel)
    result = await db_session.execute(genres_stmt)
    db_genres = result.scalars().all()
    assert (
        len(db_genres) == 2
    ), "All genres should be add to genre's table after movie creation"
    assert db_genres[0].name == "Crime", (
        "The genre should be create in the genre's table after movie creation, "
        "if it did not exist"
    )

    stars_stmt = select(StarModel)
    result = await db_session.execute(stars_stmt)
    db_stars = result.scalars().all()
    assert (
        len(db_stars) == 2
    ), "All stars should be add to star's table after movie creation"
    assert db_stars[0].name == "John Doe", (
        "The star should be create in star's table after movie creation, "
        "if it did not exist"
    )

    directors_stmt = select(DirectorModel)
    result = await db_session.execute(directors_stmt)
    db_directors = result.scalars().all()
    assert (
        len(db_directors) == 1
    ), "All directors should be add to director's table after movie creation"
    assert db_directors[0].name == "Christopher Nolan", (
        "The director should be create in director's table after movie creation, "
        "if it did not exist"
    )


@pytest.mark.asyncio
async def test_create_duplicate_movie(db_session, seed_movie_certification):
    response_first_movie = await create_movie_in_db()
    response_data = response_first_movie.json()
    assert response_first_movie.status_code == 201
    assert response_data["message"] == "Movie was created successfully!"

    response_duplicate_movie = await create_movie_in_db()
    response_data = response_duplicate_movie.json()
    assert response_duplicate_movie.status_code == 409
    assert response_data["detail"] == (
        "The movie 'The TestMovie' (2008), "
        "with a duration of 150 minutes, already exists in the database."
    )


@pytest.mark.asyncio
async def test_create_movie_no_certificate(db_session):
    """
    Test case for creating a movie if certificate id does not exist in the DB.
    """
    certification_stmt = select(CertificationModel).where(CertificationModel.id == 100)
    result = await db_session.execute(certification_stmt)
    not_existing_certification = result.scalars().first()

    assert not_existing_certification is None

    response = await create_movie_in_db()
    response_data = response.json()
    assert response.status_code == 400
    assert response_data["detail"] == "Incorrect certification id"
