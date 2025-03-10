from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def account_router():
    return {"message": "accounts of CineStreamX!"}