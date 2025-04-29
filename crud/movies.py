from typing import List, Type, Any, Optional

from fastapi import Depends, HTTPException, status, Query
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import Base, get_db
from database.models.movies import (
    MovieModel,
    GenreModel,
    StarModel,
    DirectorModel,
    CertificationModel,
)


async def get_genre_by_id(genre_id, db):
    stmt_genre = select(GenreModel).where(GenreModel.id == genre_id)
    result = await db.execute(stmt_genre)
    genre = result.scalars().first()
    if not genre:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"The genre with ID '{genre_id}' not found in DB.",
        )
    return genre


async def get_existing_movie(movie_data, db):
    stmt = select(MovieModel).where(
        MovieModel.name == movie_data.name,
        MovieModel.year == movie_data.year,
        MovieModel.time == movie_data.time,
    )
    result = await db.execute(stmt)
    existing_movie = result.scalars().first()
    return existing_movie


async def get_or_create_item(
    movies_data_items: List[str], model: Type[Any], db: AsyncSession = Depends(get_db)
):
    items = []
    for item_name in movies_data_items:
        item_stmt = select(model).where(model.name == item_name)
        item_result = await db.execute(item_stmt)
        item = item_result.scalars().first()

        if not item:
            item = model(name=item_name)
            db.add(item)
            await db.flush()
        items.append(item)

    return items


async def add_movie(movies_data, db):
    stmt = select(CertificationModel).where(
        CertificationModel.id == movies_data.certification_id
    )
    result = await db.execute(stmt)
    certification = result.scalars().first()
    if not certification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect certification id"
        )
    try:
        if movies_data.genres:
            genres = await get_or_create_item(movies_data.genres, GenreModel, db)
        if movies_data.stars:
            stars = await get_or_create_item(movies_data.stars, StarModel, db)
        if movies_data.directors:
            directors = await get_or_create_item(
                movies_data.directors, DirectorModel, db
            )
    except Exception as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation. {str(error)}",
        )

    try:
        new_movie = MovieModel(
            name=movies_data.name,
            year=movies_data.year,
            time=movies_data.time,
            imdb=movies_data.imdb,
            votes=movies_data.votes,
            meta_score=movies_data.meta_score,
            gross=movies_data.gross,
            description=movies_data.description,
            price=movies_data.price,
            certification_id=certification.id,
            genres=genres,
            stars=stars,
            directors=directors,
        )
        db.add(new_movie)
        await db.commit()
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation. {str(error)}",
        )

    await db.refresh(new_movie)
    return new_movie


async def get_movie_by_id(movie_id, db):
    stmt = (
        select(MovieModel)
        .options(
            joinedload(MovieModel.genres),
            joinedload(MovieModel.stars),
            joinedload(MovieModel.directors),
            joinedload(MovieModel.comments),
        )
        .where(MovieModel.id == movie_id)
    )
    result = await db.execute(stmt)
    movie = result.scalars().first()
    if not movie:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Movie with id '{movie_id}' not found.",
        )
    return movie


async def get_search_result(
    search_by_name_or_description, search_by_star, search_by_director, db
):
    search_result_lst = []

    stmt_stars = select(StarModel)
    result_stars = await db.execute(stmt_stars)
    stars = result_stars.scalars().all()

    stmt_directors = select(DirectorModel)
    result_directors = await db.execute(stmt_directors)
    directors = result_directors.scalars().all()

    if search_by_name_or_description:
        search_result_lst.append(
            or_(
                MovieModel.name.ilike(f"%{search_by_name_or_description}%"),
                MovieModel.description.ilike(f"%{search_by_name_or_description}%"),
            )
        )
    if search_by_star:
        matching_stars = [
            star for star in stars if search_by_star.lower() in star.name.lower()
        ]
        if matching_stars:
            search_result_lst.append(
                MovieModel.stars.any(
                    StarModel.id.in_([star.id for star in matching_stars])
                )
            )
    if search_by_director:
        matching_directors = [
            director
            for director in directors
            if search_by_director.lower() in director.name.lower()
        ]
        if matching_directors:
            search_result_lst.append(
                MovieModel.directors.any(
                    DirectorModel.id.in_([star.id for star in matching_directors])
                )
            )

    return search_result_lst


async def get_filter_result(year, imdb, filter_by_genre, db):
    filters = []
    # filtering by year
    if year:
        filters.append(MovieModel.year == year)
    # filtering by imdb
    if imdb:
        filters.append(MovieModel.imdb >= imdb)
    #  filtering by genre
    if filter_by_genre:
        stmt_genre = select(GenreModel)
        result_genre = await db.execute(stmt_genre)
        genres = result_genre.scalars().all()

        matching_genres = [
            genre for genre in genres if filter_by_genre.lower() in genre.name.lower()
        ]
        if matching_genres:
            filters.append(
                MovieModel.genres.any(
                    GenreModel.id.in_([genre.id for genre in matching_genres])
                )
            )

    return filters
