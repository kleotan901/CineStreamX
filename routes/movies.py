from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def movie_router():
    return {"message": "Hello, CineStreamX!"}
