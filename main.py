from fastapi import FastAPI


from routes import (
    account_router,
    movie_router,
)

app = FastAPI(
    title="CineStreamX API",
    description="An online cinema FastAPI project is a digital platform that allows users"
                " to select, watch, and purchase access to movies "
                "and other video materials via the internet."
)

api_version_prefix = "/api/v1"

app.include_router(
    account_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"]
)
app.include_router(
    movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"]
)

