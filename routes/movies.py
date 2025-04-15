import math
from typing import List, Optional, Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi_filters import create_filters, create_filters_from_model, FilterValues
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from watchfiles import awatch

from crud import get_existing_movie, add_movie
from crud.movies import get_movie_by_id, get_search_result, get_filter_result
from database import get_db
from database.models.movies import MovieModel, StarsMoviesModel, StarModel, DirectorModel
from schemas.movies import (
    BaseMovieSchema,
    MovieCreateSchema,
    MessageSchema,
    MovieListSchema,
    MovieListResponseSchema, MovieDetailSchema, FilterParams, GenreSchema, StarSchema, DirectorSchema,
)

router = APIRouter()
MovieFilter = create_filters()


@router.get(
    path="/movies/",
    response_model=MovieListResponseSchema,
    summary="All movies",
    description="Retrieve all movies from DB",
    status_code=status.HTTP_200_OK,
)
async def get_movies_list(
        sorting_query: FilterParams = Depends(),
        year: Optional[int] = Query(
            default=None,
            description="Filtering movies by year"
        ),
        imdb: Optional[float] = Query(
            default=None,
            description="Filtering movies by imdb"
        ),
        filter_by_genre: Optional[str] = Query(
            default=None,
            description="Filtering movies by genre"
        ),
        search_by_name_or_description: Optional[str] = Query(
            default=None,
            description="Search movies by name or description"
        ),
        search_by_star: Optional[str] = Query(
            default=None,
            description="Search movies by star"
        ),
        search_by_director: Optional[str] = Query(
            default=None,
            description="Search movies by director"
        ),
        page: int = Query(1, ge=1, description="Page number (1-based index)"),
        per_page: int = Query(10, ge=1, le=20, description="Number of items per page"),
        db: AsyncSession = Depends(get_db),
) -> MovieListResponseSchema:
    count_stmt = select(func.count(MovieModel.id))
    result_count = await db.execute(count_stmt)
    total_items = result_count.scalar() or 0
    if not total_items:
        raise HTTPException(status_code=404, detail="No movies found.")

    stmt = select(MovieModel)

    filters_lst = []
    # ✅ filtering by year, imdb, genres
    if year or imdb or filter_by_genre:
        filters_result = await get_filter_result(year, imdb, filter_by_genre, db)
        if filters_result:
            filters_lst.extend(filters_result)
        else:
            raise HTTPException(status_code=404, detail="No movies found for the selected filter.")

    # ✅ searching
    if search_by_name_or_description or search_by_star or search_by_director:
        search_result = await get_search_result(
            search_by_name_or_description, search_by_star, search_by_director, db
        )
        if search_result:
            filters_lst.extend(search_result)
        else:
            raise HTTPException(status_code=404, detail="No searching result.")

    if filters_lst:
        stmt = stmt.where(*filters_lst)

    # ✅ sorting based on sorting_query.sorted_by or default ordering
    if sorting_query and sorting_query.sorted_by:
        sort_column = getattr(MovieModel, sorting_query.sorted_by, None)
        if sort_column is not None:
            stmt = stmt.order_by(sort_column)
    else:
        order_by = MovieModel.default_order_by()
        stmt = stmt.order_by(*order_by)

    # Pagination
    offset = (page - 1) * per_page
    stmt = stmt.offset(offset).limit(per_page)

    result_movies = await db.execute(stmt)
    movies = result_movies.scalars().all()
    if not movies:
        raise HTTPException(status_code=404, detail="No movies found.")

    movie_list = [BaseMovieSchema.model_validate(movie) for movie in movies]

    total_pages = math.ceil(total_items / per_page)
    response = MovieListResponseSchema(
        movies=movie_list,
        prev_page=(
            f"/theater/movies/?page={page - 1}&per_page={per_page}"
            if page > 1
            else None
        ),
        next_page=(
            f"/theater/movies/?page={page + 1}&per_page={per_page}"
            if page < total_pages
            else None
        ),
        total_pages=total_pages,
        total_items=total_items,
    )
    return response


@router.post(
    path="/movies/",
    response_model=MessageSchema,
    summary="Movie Creation",
    description="Add new movie.",
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "description": "Conflict - Movie with this name, year and time already exists.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A movie with this name, year and time already exists."
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
)
async def create_movie(
        movies_data: MovieCreateSchema, db: AsyncSession = Depends(get_db)
) -> MessageSchema:
    existing_movie = await get_existing_movie(movies_data, db)
    if existing_movie:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The movie '{movies_data.name}' ({movies_data.year}), "
                   f"with a duration of {movies_data.time} minutes, already exists in the database.",
        )

    await add_movie(movies_data, db)

    return MessageSchema.model_validate({"message": "Movie was created successfully!"})


@router.get(
    path="/movies/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Movie detail",
    description="Movie detail information.",
    status_code=status.HTTP_200_OK,
    responses={
        404: {
            "description": "Not found - Movie with id not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Movie with id not found.."
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred."}
                }
            },
        },
    },
)
async def movie_detail(
        movie_id: int, db: AsyncSession = Depends(get_db)
) -> MovieDetailSchema:
    movie = await get_movie_by_id(movie_id, db)
    if not movie:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Movie with id not found.")

    return MovieDetailSchema.model_validate(movie)
