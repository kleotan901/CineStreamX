from fastapi import FastAPI

from routes import (
    account_router,
    movie_router,
)
from database.session_sqlite import engine
from database.models.movies import Base, MovieModel

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Movies homework",
    description="Description of project"
)

api_version_prefix = "/api/v1"

app.include_router(account_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"])
app.include_router(movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"])
