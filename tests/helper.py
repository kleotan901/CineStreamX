from fastapi import HTTPException, status

from database import UserGroupModel, UserGroupEnum


# Override require_moderator dependency to create Fake moderator
async def override_require_moderator():
    return UserGroupModel(id=1, name=UserGroupEnum.MODERATOR)


# Override require_moderator dependency that raises the exception
async def override_require_moderator_with_exception():
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access forbidden: moderator only",
    )


# Override require_moderator dependency that raises the unauthenticated_exception
async def override_require_moderator_with_unauthenticated_exception():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )
