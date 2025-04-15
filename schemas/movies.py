from datetime import datetime
from decimal import Decimal
from typing import Optional, List, Literal

from pydantic import BaseModel, Field

from schemas.examples.movies import (
    star_schema_example,
    genre_schema_example,
    director_schema_example,
    movie_detail_schema_example,
    certification_schema_example,
    movie_list_response_schema_example,
)


class BaseMovieSchema(BaseModel):
    name: str = Field(..., max_length=250)
    year: int = Field(..., lt=datetime.now().year)
    time: int = Field(..., ge=0)
    imdb: float
    votes: float
    meta_score: Optional[float] = None
    gross: Optional[float] = None
    description: str
    price: Decimal = Field(..., ge=0)

    model_config = {"from_attributes": True}


class MovieListSchema(BaseModel):
    movies: List[BaseMovieSchema]


class MovieListResponseSchema(BaseModel):
    movies: List[BaseMovieSchema]
    prev_page: Optional[str]
    next_page: Optional[str]
    total_pages: int
    total_items: int

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_list_response_schema_example]},
    }


class FilterParams(BaseModel):
    sorted_by: Literal["year", "name", "price", "imdb"] = "year"


class MovieCreateSchema(BaseMovieSchema):
    certification_id: int = 1

    genres: Optional[List[str]] = None
    stars: Optional[List[str]] = None
    directors: Optional[List[str]] = None

    model_config = {"from_attributes": True}


class MessageSchema(BaseModel):
    message: str


class DirectorSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [director_schema_example]},
    }


class GenreSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [genre_schema_example]},
    }


class StarSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [star_schema_example]},
    }


class CertificationSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [certification_schema_example]},
    }


class MovieDetailSchema(BaseMovieSchema):
    id: int

    genres: List[GenreSchema] = None
    stars: List[StarSchema] = None
    directors: List[DirectorSchema] = None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_detail_schema_example]},
    }
