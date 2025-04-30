import math
from typing import Optional, Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi_filters import create_filters
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import get_user_id_from_headers
from crud import (
    get_movie_by_id,
    get_existing_movie,
    add_movie,
    update_movie_by_id,
    delete_movie_by_id,
    get_search_result,
    get_filter_result,
    get_genre_by_id,
)

from database import get_db
from database.models.movies import (
    MovieModel,
    MovieLikeModel,
    CommentModel,
    FavoriteMovieModel,
    GenreModel,
    MoviesGenresModel,
)
from schemas.movies import (
    BaseMovieSchema,
    MovieCreateSchema,
    MessageSchema,
    MovieListResponseSchema,
    MovieDetailSchema,
    FilterParams,
    CommentInputSchema,
    GenreListSchema,
    MoviesCountByGenreSchema,
    MoviesByGenreSchema,
    MovieUpdateSchema,
)

router = APIRouter()
MovieFilter = create_filters()


async def common_parameters(
        sorting_query: FilterParams = Depends(),
        year: Optional[int] = Query(default=None, description="Filtering movies by year"),
        imdb: Optional[float] = Query(default=None, description="Filtering movies by imdb"),
        filter_by_genre: Optional[str] = Query(
            default=None, description="Filtering movies by genre"
        ),
        search_by_name_or_description: Optional[str] = Query(
            default=None, description="Search movies by name or description"
        ),
        search_by_star: Optional[str] = Query(
            default=None, description="Search movies by star"
        ),
        search_by_director: Optional[str] = Query(
            default=None, description="Search movies by director"
        ),
        page: int = Query(1, ge=1, description="Page number (1-based index)"),
        per_page: int = Query(10, ge=1, le=20, description="Number of items per page"),
):
    return {
        "sorting_query": sorting_query,
        "year": year,
        "imdb": imdb,
        "filter_by_genre": filter_by_genre,
        "search_by_name_or_description": search_by_name_or_description,
        "search_by_star": search_by_star,
        "search_by_director": search_by_director,
        "page": page,
        "per_page": per_page,
    }


@router.get(
    path="/movies/",
    response_model=MovieListResponseSchema,
    summary="All movies",
    description="Retrieve all movies from DB",
    status_code=status.HTTP_200_OK,
)
async def get_movies_list(
        commons: Annotated[dict, Depends(common_parameters)],
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
    if commons["year"] or commons["imdb"] or commons["filter_by_genre"]:
        filters_result = await get_filter_result(
            commons["year"], commons["imdb"], commons["filter_by_genre"], db
        )
        if filters_result:
            filters_lst.extend(filters_result)
        else:
            raise HTTPException(
                status_code=404, detail="No movies found for the selected filter."
            )

    # ✅ searching
    if (
            commons["search_by_name_or_description"]
            or commons["search_by_star"]
            or commons["search_by_director"]
    ):
        search_result = await get_search_result(
            commons["search_by_name_or_description"],
            commons["search_by_star"],
            commons["search_by_director"],
            db,
        )
        if search_result:
            filters_lst.extend(search_result)
        else:
            raise HTTPException(status_code=404, detail="No searching result.")

    if filters_lst:
        stmt = stmt.where(*filters_lst)

    # ✅ sorting based on sorting_query.sorted_by or default ordering
    if commons["sorting_query"] and commons["sorting_query"].sorted_by:
        sort_column = getattr(MovieModel, commons["sorting_query"].sorted_by, None)
        if sort_column is not None:
            stmt = stmt.order_by(sort_column)
    else:
        order_by = MovieModel.default_order_by()
        stmt = stmt.order_by(*order_by)

    # Pagination
    offset = (commons["page"] - 1) * commons["per_page"]
    stmt = stmt.offset(offset).limit(commons["per_page"])

    result_movies = await db.execute(stmt)
    movies = result_movies.scalars().all()
    if not movies:
        raise HTTPException(status_code=404, detail="No movies found.")

    movie_list = [BaseMovieSchema.model_validate(movie) for movie in movies]

    total_pages = math.ceil(total_items / commons["per_page"])
    response = MovieListResponseSchema(
        movies=movie_list,
        prev_page=(
            f"/theater/movies/?page={commons["page"] - 1}&per_page={commons["per_page"]}"
            if commons["page"] > 1
            else None
        ),
        next_page=(
            f"/theater/movies/?page={commons["page"] + 1}&per_page={commons["per_page"]}"
            if commons["page"] < total_pages
            else None
        ),
        total_pages=total_pages,
        total_items=total_items,
    )
    return response


@router.get(
    path="/genres/",
    response_model=GenreListSchema,
    summary="A list of genres with the count of movies in each.",
    description="View a list of genres with the count of movies in each. "
                "Clicking on a genre shows all related movies.",
    status_code=status.HTTP_200_OK,
)
async def get_genres_with_movie_count(
        db: AsyncSession = Depends(get_db),
) -> GenreListSchema:
    stmt = (
        select(
            GenreModel.id,
            GenreModel.name,
            func.count(MovieModel.id).label("movie_count"),
        )
        .join(MoviesGenresModel, GenreModel.id == MoviesGenresModel.c.genre_id)
        .join(MovieModel, MoviesGenresModel.c.movie_id == MovieModel.id)
        .group_by(GenreModel.id)
        .order_by(GenreModel.name)
    )
    result_genre = await db.execute(stmt)
    genres_data = result_genre.all()

    genres = [
        MoviesCountByGenreSchema(id=id_, genre_name=name, movie_count=movie_count)
        for id_, name, movie_count in genres_data
    ]

    return GenreListSchema(genres=genres)


@router.get(
    path="/movies-by-genre/{genre_id}/",
    response_model=MoviesByGenreSchema,
    summary="A list of movies by genre_id.",
    description="Clicking on a genre shows all related movies.",
    status_code=status.HTTP_200_OK,
)
async def get_movies_by_genre(
        genre_id: int, db: AsyncSession = Depends(get_db)
) -> MoviesByGenreSchema:
    genre = await get_genre_by_id(genre_id, db)

    stmt_movies = (
        select(MovieModel).join(MovieModel.genres).where(GenreModel.id == genre_id)
    )
    result = await db.execute(stmt_movies)
    movies = result.scalars().all()

    movies_list = [movie for movie in movies]

    return MoviesByGenreSchema(
        id=genre_id,
        genre_name=genre.name,
        movie_count=len(movies_list),
        movies=movies_list,
    )


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
    path="/movies/favorites/",
    response_model=MovieListResponseSchema,
    summary="All favorite movies of authorized user",
    description="Retrieve all favorite movies of authorized user from DB",
    status_code=status.HTTP_200_OK,
)
async def get_favorite_movies_list(
        commons: Annotated[dict, Depends(common_parameters)],
        user_id: int = Depends(get_user_id_from_headers),
        db: AsyncSession = Depends(get_db),
) -> MovieListResponseSchema:
    stmt_favorites = (
        select(MovieModel)
        .join(FavoriteMovieModel, FavoriteMovieModel.movie_id == MovieModel.id)
        .where(FavoriteMovieModel.user_id == user_id)
    )

    filters_lst = []
    # ✅ filtering by year, imdb, genres
    if commons["year"] or commons["imdb"] or commons["filter_by_genre"]:
        filters_result = await get_filter_result(
            commons["year"], commons["imdb"], commons["filter_by_genre"], db
        )
        if filters_result:
            filters_lst.extend(filters_result)
        else:
            raise HTTPException(
                status_code=404, detail="No movies found for the selected filter."
            )

    # ✅ searching
    if (
            commons["search_by_name_or_description"]
            or commons["search_by_star"]
            or commons["search_by_director"]
    ):
        search_result = await get_search_result(
            commons["search_by_name_or_description"],
            commons["search_by_star"],
            commons["search_by_director"],
            db,
        )
        if search_result:
            filters_lst.extend(search_result)
        else:
            raise HTTPException(status_code=404, detail="No searching result.")

    if filters_lst:
        stmt_favorites = stmt_favorites.where(*filters_lst)

    # ✅ sorting based on sorting_query.sorted_by or default ordering
    if commons["sorting_query"] and commons["sorting_query"].sorted_by:
        sort_column = getattr(MovieModel, commons["sorting_query"].sorted_by, None)
        if sort_column is not None:
            stmt_favorites = stmt_favorites.order_by(sort_column)
    else:
        order_by = MovieModel.default_order_by()
        stmt_favorites = stmt_favorites.order_by(*order_by)

    # Pagination
    offset = (commons["page"] - 1) * commons["per_page"]
    stmt_favorites = stmt_favorites.offset(offset).limit(commons["per_page"])

    result_movies = await db.execute(stmt_favorites)
    movies = result_movies.scalars().all()
    if not movies:
        raise HTTPException(status_code=404, detail="No movies in favorites.")
    total_items = len(movies)

    movie_list = [BaseMovieSchema.model_validate(movie) for movie in movies]

    total_pages = math.ceil(total_items / commons["per_page"])
    response = MovieListResponseSchema(
        movies=movie_list,
        prev_page=(
            f"/theater/movies/?page={commons["page"] - 1}&per_page={commons["per_page"]}"
            if commons["page"] > 1
            else None
        ),
        next_page=(
            f"/theater/movies/?page={commons["page"] + 1}&per_page={commons["per_page"]}"
            if commons["page"] < total_pages
            else None
        ),
        total_pages=total_pages,
        total_items=total_items,
    )
    return response


@router.post(
    path="/movies/add-to-favorite/",
    response_model=MessageSchema,
    summary="Add movie to favorite.",
    description="Add movie to favorite.",
    status_code=status.HTTP_201_CREATED,
)
async def add_movie_to_favorites(
        movie_id: int,
        user_id: int = Depends(get_user_id_from_headers),
        db: AsyncSession = Depends(get_db),
) -> MessageSchema:
    movie = await get_movie_by_id(movie_id, db)
    try:
        favorite_movie = FavoriteMovieModel(user_id=user_id, movie_id=movie_id)
        db.add(favorite_movie)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The movie already in favorites.",
        )

    return MessageSchema.model_validate(
        {"message": f"Movie {movie.name} add to favorites!"}
    )


@router.delete(
    path="/movies/remove-from-favorite/",
    response_model=MessageSchema,
    summary="Remove movie from favorite.",
    description="Remove movie from favorite.",
    status_code=status.HTTP_200_OK,
)
async def remove_from_favorites(
        movie_id: int,
        user_id: int = Depends(get_user_id_from_headers),
        db: AsyncSession = Depends(get_db),
) -> MessageSchema:
    movie = await get_movie_by_id(movie_id, db)
    try:
        result = await db.execute(
            select(FavoriteMovieModel).where(
                FavoriteMovieModel.movie_id == movie_id,
                FavoriteMovieModel.user_id == user_id,
            )
        )
        db_favorite_movie = result.scalar_one_or_none()
        if not db_favorite_movie:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This movie is not in favorites.",
            )
        await db.delete(db_favorite_movie)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The movie is not in favorites.",
        )

    return MessageSchema.model_validate(
        {"message": f"Movie {movie.name} was removed from favorites!"}
    )


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
                "application/json": {"example": {"detail": "Movie with id not found.."}}
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred.",
            "content": {
                "application/json": {"example": {"detail": "An error occurred."}}
            },
        },
    },
)
async def movie_detail(
        movie_id: int, db: AsyncSession = Depends(get_db)
) -> MovieDetailSchema:
    movie = await get_movie_by_id(movie_id, db)
    return MovieDetailSchema.model_validate(movie)


@router.put(
    path="/movies/update/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Update movie.",
    description="Update movie.",
    status_code=status.HTTP_200_OK,
)
async def edit_movie(
        movie_id: int, movie_data: MovieUpdateSchema, db: AsyncSession = Depends(get_db)
) -> MovieDetailSchema:
    updated_film = await update_movie_by_id(movie_id, movie_data, db)
    return MovieDetailSchema.model_validate(updated_film)


@router.delete(
    path="/movies/delete/{movie_id}/",
    response_model=MessageSchema,
    summary="Delete movie.",
    description="Delete movie.",
    status_code=status.HTTP_200_OK,
)
async def remove_movie(
        movie_id: int, db: AsyncSession = Depends(get_db)
) -> MessageSchema:
    await delete_movie_by_id(movie_id, db)
    return MessageSchema.model_validate({"message": "Film was deleted!"})


@router.patch(
    path="/movies/is_like/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Like or dislike movies (Authorization required)",
    description="Set is_like True or False and count likes or dislikes.",
    status_code=status.HTTP_200_OK,
)
async def movie_like(
        movie_id: int,
        input_is_like: bool = None,
        user_id: int = Depends(get_user_id_from_headers),
        db: AsyncSession = Depends(get_db),
) -> MovieDetailSchema:
    movie = await get_movie_by_id(movie_id, db)
    stmt = select(MovieLikeModel).where(
        MovieLikeModel.movie_id == movie_id, MovieLikeModel.user_id == user_id
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing is None:
        if input_is_like is True:
            db.add(MovieLikeModel(user_id=user_id, movie_id=movie_id, is_like=True))
            await db.execute(
                update(MovieModel)
                .where(MovieModel.id == movie_id)
                .values(likes_count=MovieModel.likes_count + 1)
            )
        if input_is_like is False:
            db.add(MovieLikeModel(user_id=user_id, movie_id=movie_id, is_like=False))
            await db.execute(
                update(MovieModel)
                .where(MovieModel.id == movie_id)
                .values(
                    dislikes_count=MovieModel.dislikes_count + 1,
                )
            )
    else:
        if existing.is_like is True and input_is_like is True:
            return MovieDetailSchema.model_validate(movie)
        if existing.is_like is False and input_is_like is False:
            return MovieDetailSchema.model_validate(movie)
        if existing.is_like is True and input_is_like is False:
            print("existing.is_like", existing.is_like, "input_is_like", input_is_like)
            existing.is_like = False
            await db.execute(
                update(MovieModel)
                .where(MovieModel.id == movie_id)
                .values(
                    likes_count=MovieModel.likes_count - 1,
                    dislikes_count=MovieModel.dislikes_count + 1,
                )
            )
        if existing.is_like is False and input_is_like is True:
            existing.is_like = True
            await db.execute(
                update(MovieModel)
                .where(MovieModel.id == movie_id)
                .values(
                    likes_count=MovieModel.likes_count + 1,
                    dislikes_count=MovieModel.dislikes_count - 1,
                )
            )
    await db.commit()

    return MovieDetailSchema.model_validate(movie)


@router.post(
    path="/movies/comment/{movie_id}/",
    response_model=MessageSchema,
    summary="Add comment for movie (Authorization required)",
    description="Post comment for movie.",
    status_code=status.HTTP_201_CREATED,
)
async def create_comment(
        movie_id: int,
        comment_data: CommentInputSchema,
        user_id: int = Depends(get_user_id_from_headers),
        db: AsyncSession = Depends(get_db),
) -> MessageSchema:
    if not comment_data.comment.strip():
        raise HTTPException(status_code=400, detail="Comment cannot be empty")

    try:
        db.add(
            CommentModel(
                user_id=user_id, movie_id=movie_id, comment=comment_data.comment.strip()
            )
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create comment due to integrity error.",
        )

    return MessageSchema.model_validate(
        {"message": "Comment was created successfully!"}
    )
