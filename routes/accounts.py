from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BASE_URL
from config.dependencies import (
    get_jwt_auth_manager,
    get_settings,
    get_accounts_email_notificator,
    require_admin,
)
from config.settings import BaseAppSettings
from crud import (
    get_user_by_email,
    create_user,
    get_activation_token,
    create_activation_token,
    delete_activation_token
)
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions.security import BaseSecurityError, InvalidTokenError, TokenExpiredError
from notifications import EmailSenderInterface

from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    ActivationTokenRequestSchema,
    MessageResponseSchema,
    ActivationAccountCompleteSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserLogoutRequestSchema,
    UserChangePasswordRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserUpdateSchema,
)
from security.interfaces import JWTAuthManagerInterface

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
        email_sender: EmailSenderInterface = Depends(get_accounts_email_notificator),
) -> UserRegistrationResponseSchema:
    db_user = await get_user_by_email(user_data.email, db)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        new_user = await create_user(user_data, db)
        # Check if an existing activation token exists for the user
        stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == new_user.id)
        result = await db.execute(stmt)
        existing_token = result.scalars().first()
        if existing_token:
            await db.delete(existing_token)
            await db.commit()  # Ensure deletion before inserting a new token

        await create_activation_token(new_user, db)

        activation_link = f"{BASE_URL}accounts/activate-complete/"
        await email_sender.send_activation_email(new_user.email, activation_link)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation.",
        )

    except Exception as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Server Error --- {str(error)} ---",
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
                            "value": {"detail": "User account is already active."},
                        },
                    }
                }
            },
        },
    },
)
async def activate_token(
        activation_data: ActivationTokenRequestSchema,
        db: AsyncSession = Depends(get_db),
        email_sender: EmailSenderInterface = Depends(get_accounts_email_notificator),
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

    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == existing_user.id
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if not activation_token:
        activation_token = await create_activation_token(existing_user, db)

    now_utc = datetime.now(timezone.utc)
    if (
            cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
            < now_utc
    ):
        await delete_activation_token(activation_token, db)
        await create_activation_token(existing_user, db)

    activate_link = f"{BASE_URL}accounts/activate-complete/"
    await email_sender.send_activation_email(str(activation_data.email), activate_link)

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
                            "value": {"detail": "Invalid or expired activation token."},
                        },
                        "already_active": {
                            "summary": "Account Already Active",
                            "value": {"detail": "User account is already active."},
                        },
                    }
                }
            },
        },
    },
)
async def account_activation_complete(
        activation_complete_data: ActivationAccountCompleteSchema,
        db: AsyncSession = Depends(get_db),
        email_sender: EmailSenderInterface = Depends(get_accounts_email_notificator),
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

    login_link = f"{BASE_URL}accounts/login/"
    await email_sender.send_activation_complete_email(user.email, login_link)

    return MessageResponseSchema(message="Account was successfully activated!")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User Login",
    description="Authenticate a user and return access and refresh tokens.",
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {
            "description": "Unauthorized - Invalid email or password.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or password."}
                }
            },
        },
        403: {
            "description": "Forbidden - User account is not activated.",
            "content": {
                "application/json": {
                    "example": {"detail": "User account is not activated."}
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred while processing the request.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while processing the request."
                    }
                }
            },
        },
    },
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> UserLoginResponseSchema:
    """
    Endpoint for user login.

    Authenticates a user using their email and password.
    If authentication is successful, creates a new refresh token and returns both access and refresh tokens.

    Args:
        login_data (UserLoginRequestSchema): The login credentials.
        db (AsyncSession): The asynchronous database session.
        settings (BaseAppSettings): The application settings.
        jwt_manager (JWTAuthManagerInterface): The JWT authentication manager.
    Returns:
        UserLoginResponseSchema: A response containing the access and refresh tokens.
    Raises:
        HTTPException:
            - 401 Unauthorized if the email or password is invalid.
            - 403 Forbidden if the user account is not activated.
            - 500 Internal Server Error if an error occurs during token creation.
    """
    stmt = select(UserModel).filter_by(email=login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    jwt_access_token = jwt_manager.create_access_token(
        {"user_id": user.id, "group_id": user.group_id, "email":user.email}
    )
    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )


@router.post(
    "/logout/",
    response_model=MessageResponseSchema,
    summary="User Logout",
    description="Logout user and remove refresh token.",
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Unauthorized - Invalid email or password.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or password."}
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred while processing the request.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while processing the request."
                    }
                }
            },
        },
    },
)
async def logout_user(
        logout_data: UserLogoutRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> MessageResponseSchema:
    """
    Endpoint for user logout.
    Args:
        logout_data (UserLogoutRequestSchema): The logout data.
        db (AsyncSession): The asynchronous database session.
        jwt_manager (JWTAuthManagerInterface): JWT authentication manager.
    Returns:
        MessageResponseSchema: A response containing success logged out message.
    Raises:
        HTTPException:
            - 400 BAD REQUEST if refresh token is invalid.
            - 500 Internal Server Error if an error occurs during token creation.
    """
    try:
        jwt_manager.decode_refresh_token(logout_data.refresh_token)
        stmt = select(RefreshTokenModel).filter_by(token=logout_data.refresh_token)
        result = await db.execute(stmt)
        db_refresh_token = result.scalars().first()
        await db.delete(db_refresh_token)
        await db.commit()

    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return MessageResponseSchema(message="User logged out!")


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh Access Token",
    description="Refresh the access token using a valid refresh token.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The provided refresh token is invalid or expired.",
            "content": {
                "application/json": {"example": {"detail": "Token has expired."}}
            },
        },
        401: {
            "description": "Unauthorized - Refresh token not found.",
            "content": {
                "application/json": {"example": {"detail": "Refresh token not found."}}
            },
        },
        404: {
            "description": "Not Found - The user associated with the token does not exist.",
            "content": {"application/json": {"example": {"detail": "User not found."}}},
        },
    },
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """
    Endpoint to refresh an access token.

    Validates the provided refresh token, extracts the user ID from it, and issues
    a new access token. If the token is invalid or expired, an error is returned.

    Args:
        token_data (TokenRefreshRequestSchema): Contains the refresh token.
        db (AsyncSession): The asynchronous database session.
        jwt_manager (JWTAuthManagerInterface): JWT authentication manager.

    Returns:
        TokenRefreshResponseSchema: A new access token.

    Raises:
        HTTPException:
            - 400 Bad Request if the token is invalid or expired.
            - 401 Unauthorized if the refresh token is not found.
            - 404 Not Found if the user associated with the token does not exist.
    """
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    stmt = select(RefreshTokenModel).filter_by(token=token_data.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()
    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    stmt = select(UserModel).filter_by(id=user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token(
        {"user_id": user_id, "group_id": user.group_id, "email":user.email}
    )

    return TokenRefreshResponseSchema(access_token=new_access_token)


@router.post(
    path="/change-password/",
    response_model=MessageResponseSchema,
    summary="Change password",
    description="Users can change their password if they remember the old one "
                "by entering the old password and a new password.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The provided access token is invalid or expired.",
            "content": {
                "application/json": {
                    "example": {"detail": "Token is invalid or expired."}
                }
            },
        },
        401: {
            "description": "Unauthorized - Password or email is invalid.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or old password."}
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
async def change_password(
        user_data: UserChangePasswordRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> MessageResponseSchema:
    db_user = await get_user_by_email(user_data.email, db)
    if not db_user or not db_user.verify_password(user_data.old_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid provided email or password.",
        )

    try:
        decode_access_token = jwt_manager.decode_access_token(
            token=user_data.access_token
        )
        if decode_access_token["user_id"] != db_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid access token."
            )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid access token."
        )

    try:
        db_user.password = user_data.new_password
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password was changed successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request Password Reset Token",
    description=(
            "Allows a user to request a password reset token. If the user exists and is active, "
            "a new token will be generated and any existing tokens will be invalidated."
    ),
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
        email_sender: EmailSenderInterface = Depends(get_accounts_email_notificator),
) -> MessageResponseSchema:
    """
    Endpoint to request a password reset token.
    If the user exists and is active, invalidates any existing password reset tokens and generates a new one.
    Always responds with a success message to avoid leaking user information.
    Args:
        data (PasswordResetRequestSchema): The request data containing the user's email.
        db (AsyncSession): The asynchronous database session.
        email_sender (EmailSenderInterface): The asynchronous email sender.
    Returns:
        MessageResponseSchema: A success message indicating that instructions will be sent.
    """
    user = await get_user_by_email(data.email, db)
    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    password_reset_complete_link = f"{BASE_URL}/password-reset-complete/"
    await email_sender.send_password_reset_email(
        str(data.email), password_reset_complete_link
    )

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Reset User Password",
    description="Reset a user's password if a valid token is provided.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": (
                    "Bad Request - The provided email or token is invalid, "
                    "the token has expired, or the user account is not active."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_email_or_token": {
                            "summary": "Invalid Email or Token",
                            "value": {"detail": "Invalid email or token."},
                        },
                        "expired_token": {
                            "summary": "Expired Token",
                            "value": {"detail": "Invalid email or token."},
                        },
                    }
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred while resetting the password.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while resetting the password."
                    }
                }
            },
        },
    },
)
async def reset_password(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
        email_sender: EmailSenderInterface = Depends(get_accounts_email_notificator),
) -> MessageResponseSchema:
    """
    Endpoint for resetting a user's password.
    Validates the token and updates the user's password if the token is valid and not expired.
    Deletes the token after a successful password reset.
    Args:
        data (PasswordResetCompleteRequestSchema): The request data containing the user's email,
         token, and new password.
        db (AsyncSession): The asynchronous database session.
        email_sender (EmailSenderInterface): The asynchronous email sender.

    Returns:
        MessageResponseSchema: A response message indicating successful password reset.

    Raises:
        HTTPException:
            - 400 Bad Request if the email or token is invalid, or the token has expired.
            - 500 Internal Server Error if an error occurs during the password reset process.
    """
    user = await get_user_by_email(data.email, db)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    stmt = select(PasswordResetTokenModel).filter_by(user_id=user.id)
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record or token_record.token != data.token:
        if token_record:
            await db.run_sync(lambda s: s.delete(token_record))
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.run_sync(lambda s: s.delete(token_record))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user.password = data.password
        await db.run_sync(lambda s: s.delete(token_record))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    login_link = f"{BASE_URL}/accounts/login/"
    await email_sender.send_password_reset_complete_email(str(data.email), login_link)

    return MessageResponseSchema(message="Password reset successfully.")


@router.put("/{user_id}/manage-user/")
async def manage_user(
        user_id: int,
        user_data: UserUpdateSchema,
        db: AsyncSession = Depends(get_db),
        current_user=Depends(require_admin),
) -> MessageResponseSchema:
    """
        Endpoint for managing users, change group memberships and manually activate accounts.
        Args:
            user_id: int user's ID.
            user_data (UserUpdateSchema): user's data for updating.
            db (AsyncSession): The asynchronous database session.
            current_user: The depends on require_admin,
                only user with admin rights can manage date of other users.
        Returns:
            MessageResponseSchema: A response message indicating successful update user's data.
        Raises:
            HTTPException:
                - 400 Bad Request if user's group does not exist in DB.
                - 404 User not found.
                - 403 Access forbidden: admins only.
                - 401 Unauthorized error.
        """
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user_obj = result.scalar_one_or_none()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        input_group_name = UserGroupEnum[user_data.group.upper()]
        stmt = select(UserGroupModel).filter_by(name=input_group_name)
        result = await db.execute(stmt)
        db_group = result.scalars().first()

        user_obj.group_id = db_group.id
        user_obj.is_active = user_data.is_active
        await db.commit()
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The group does not exist!",
        )
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"An error occurred {str(error)}",
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while user's data updating.",
        )
    return MessageResponseSchema(message="User was updated successfully!")
