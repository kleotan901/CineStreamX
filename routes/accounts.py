from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import BASE_URL
from crud import get_user_by_email, create_user, get_activation_token, create_activation_token, delete_activation_token
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema, ActivationTokenRequestSchema, MessageResponseSchema,
    ActivationAccountCompleteSchema,
)

router = APIRouter()


@router.post(
    path="/register/",
    response_model=UserRegistrationResponseSchema,
    summary="User Registration",
    description="Register new user with an email and password.",
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "description": "Conflict - User with this email already exists.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A user with this email test@example.com already exists."
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
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    db_user = await get_user_by_email(user_data.email, db)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        new_user = await create_user(user_data, db)
        await create_activation_token(new_user, db)

        # TODO send email with activation_token link
        link = f"{BASE_URL}accounts/activate-complete/"
        print(f"------send email with  account_activation_complete link {link}------")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Server Error --- {str(e)} ---",
        )

    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    path="/activate/",
    response_model=MessageResponseSchema,
    summary="Request for account activation token",
    description="Send new activation link, "
                "if the user fails to activate their account within 24 hours",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The activation token is invalid or expired, "
                           "or the user account is already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {
                                "detail": "User account is already active."
                            }
                        },
                    }
                }
            },
        },
    }
)
async def activate_token(
    activation_data: ActivationTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    existing_user = await get_user_by_email(activation_data.email, db)
    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="A user with this email not found.",
        )
    if existing_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is already active.",
        )

    stmt = (
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == existing_user.id)
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if not activation_token:
        activation_token = await create_activation_token(existing_user, db)

    now_utc = datetime.now(timezone.utc)
    if cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc) < now_utc:
        await delete_activation_token(activation_token, db)
        await create_activation_token(existing_user, db)

    # TODO send email with account_activation_complete link
    link = f"{BASE_URL}accounts/activate-complete/"
    print(f"------send email with  account_activation_complete link {link}------")

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    path="/activate-complete/",
    response_model=MessageResponseSchema,
    summary="Account activation complete",
    description="Complete user's account activation.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The activation token is invalid or expired, "
                           "or the user account is already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid Token",
                            "value": {
                                "detail": "Invalid or expired activation token."
                            }
                        },
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {
                                "detail": "User account is already active."
                            }
                        },
                    }
                }
            },
        },
    }
)
async def account_activation_complete(
    activation_complete_data: ActivationAccountCompleteSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    token_record = await get_activation_token(activation_complete_data, db)

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid activation token or account is already active.",
        )
    now_utc = datetime.now(timezone.utc)
    if cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < now_utc:
        await delete_activation_token(token_record, db)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user = token_record.user
    user.is_active = True
    await delete_activation_token(token_record, db)

    return MessageResponseSchema(
        message="Account was successfully activated!"
    )
