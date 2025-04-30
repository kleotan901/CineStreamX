from typing import List, Type, Any, Optional

from fastapi import Depends, HTTPException, status, Query
from sqlalchemy import select, or_
from sqlalchemy.exc import IntegrityError
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
            detail=f"An error occurred during genres, stars or directors creation. {str(error)}",
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
            detail=f"An error occurred during movie creation. {str(error)}",
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


async def update_movie_by_id(movie_id, movies_data, db):
    db_film = await get_movie_by_id(movie_id=movie_id, db=db)
    try:
        db_film.name = movies_data.name
        db_film.year = movies_data.year
        db_film.time = movies_data.time
        db_film.imdb = movies_data.imdb
        db_film.votes = movies_data.votes
        db_film.meta_score = movies_data.meta_score
        db_film.gross = movies_data.gross
        db_film.description = movies_data.description
        db_film.price = movies_data.price
        db_film.certification_id = movies_data.certification_id
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
                detail=f"An error occurred during genres, stars or directors updating. {str(error)}",
            )

        db_film.genres = genres
        db_film.stars = stars
        db_film.directors = directors

        await db.commit()
        await db.refresh(db_film)

    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during movie updating. {str(error)}",
        )

    return db_film


async def delete_movie_by_id(movie_id, db):
    db_film = await get_movie_by_id(movie_id=movie_id, db=db)
    await db.delete(db_film)
    await db.commit()
    return db_film


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


async def add_genre(genre_data, db):
    try:
        new_genre = GenreModel(name=genre_data.name)
        db.add(new_genre)
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The genre '{genre_data.name}' already exist in DB.",
        )
    db.refresh(new_genre)
    return new_genre


async def update_genre_by_id(genre_id, genre_data, db):
    db_genre = await get_genre_by_id(genre_id, db)
    try:
        db_genre.name = genre_data.name
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The genre '{genre_data.name}' already exist in DB.",
        )
    db.refresh(db_genre)
    return db_genre


async def delete_genre_by_id(genre_id, db):
    db_genre = await get_genre_by_id(genre_id, db)
    try:
        await db.delete(db_genre)
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An error occurred during deletion genre - {str(error)}",
        )
    return db_genre


async def add_star(star_data, db):
    try:
        new_star = StarModel(name=star_data.name)
        db.add(new_star)
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The star with name - '{star_data.name}' already exists in DB.",
        )
    db.refresh(new_star)
    return new_star


async def update_star_by_id(star_id, star_data, db):
    stmt = select(StarModel).where(StarModel.id == star_id)
    result = await db.execute(stmt)
    db_star = result.scalars().first()
    try:
        db_star.name = star_data.name
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The star with name - '{star_data.name}' already exists in DB.",
        )
    db.refresh(db_star)
    return db_star


async def delete_star_by_id(star_id, db):
    stmt = select(StarModel).where(StarModel.id == star_id)
    result = await db.execute(stmt)
    db_star = result.scalars().first()
    try:
        await db.delete(db_star)
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An error occurred during deletion star - {str(error)}",
        )
    return db_star
