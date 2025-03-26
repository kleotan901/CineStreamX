import os

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import TestingSettings, Settings, BaseAppSettings

from database import get_db, UserModel, UserGroupModel, UserGroupEnum
from exceptions import TokenExpiredError, InvalidTokenError
from notifications import EmailSenderInterface, EmailSender

from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager


def get_settings() -> BaseAppSettings:
    """
    Retrieve the application settings based on the current environment.

    This function reads the 'ENVIRONMENT' environment variable (defaulting to 'developing' if not set)
    and returns a corresponding settings instance. If the environment is 'testing', it returns an instance
    of TestingSettings; otherwise, it returns an instance of Settings.

    Returns:
        BaseAppSettings: The settings instance appropriate for the current environment.
    """
    environment = os.getenv("ENVIRONMENT", "developing")
    if environment == "testing":
        return TestingSettings()
    return Settings()


def get_jwt_auth_manager(
        settings: BaseAppSettings = Depends(get_settings),
) -> JWTAuthManagerInterface:
    """
    Create and return a JWT authentication manager instance.

    This function uses the provided application settings to instantiate a JWTAuthManager, which implements
    the JWTAuthManagerInterface. The manager is configured with secret keys for access and refresh tokens
    as well as the JWT signing algorithm specified in the settings.

    Args:
        settings (BaseAppSettings, optional): The application settings instance.
        Defaults to the output of get_settings().

    Returns:
        JWTAuthManagerInterface: An instance of JWTAuthManager configured with
        the appropriate secret keys and algorithm.
    """
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM,
    )


def get_accounts_email_notificator(
        settings: BaseAppSettings = Depends(get_settings),
) -> EmailSenderInterface:
    """
    Retrieve an instance of the EmailSenderInterface configured with the application settings.

    This function creates an EmailSender using the provided settings, which include details such as the email host,
    port, credentials, TLS usage, and the directory and filenames for email templates. This allows the application
    to send various email notifications (e.g., activation, password reset) as required.

    Args:
        settings (BaseAppSettings, optional): The application settings,
        provided via dependency injection from `get_settings`.

    Returns:
        EmailSenderInterface: An instance of EmailSender configured with the appropriate email settings.
    """
    return EmailSender(
        hostname=settings.EMAIL_HOST,
        port=settings.EMAIL_PORT,
        email=settings.EMAIL_HOST_USER,
        password=settings.EMAIL_HOST_PASSWORD,
        use_tls=settings.EMAIL_USE_TLS,
        template_dir=settings.PATH_TO_EMAIL_TEMPLATES_DIR,
        activation_email_template_name=settings.ACTIVATION_EMAIL_TEMPLATE_NAME,
        activation_complete_email_template_name=settings.ACTIVATION_COMPLETE_EMAIL_TEMPLATE_NAME,
        password_email_template_name=settings.PASSWORD_RESET_TEMPLATE_NAME,
        password_complete_email_template_name=settings.PASSWORD_RESET_COMPLETE_TEMPLATE_NAME,
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def require_admin(
        token: str = Depends(oauth2_scheme),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db),
) -> UserGroupModel:
    """
    Dependency to enforce admin access.

    This function:
    - Decodes the provided JWT access token.
    - Verifies if the token is valid and not expired.
    - Retrieves the user's group from the database.
    - Ensures the user belongs to the "ADMIN" group.

    Raises:
        HTTPException (401): If the token is missing, invalid, or expired.
        HTTPException (403): If the user does not have admin privileges.

    Returns:
        UserGroupModel: The admin group object if access is granted.
    """
    try:
        payload = jwt_manager.decode_access_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token!")

    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    stmt = select(UserGroupModel).filter(UserGroupModel.id == payload.get("group_id"))
    result = await db.execute(stmt)
    group = result.scalars().first()
    if not group:
        raise HTTPException(status_code=403, detail="Access forbidden: admins only")
    if group.name != UserGroupEnum.ADMIN:
        raise HTTPException(status_code=403, detail="Access forbidden: admins only")

    return group


async def require_moderator(
        token: str = Depends(oauth2_scheme),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db),
) -> UserGroupModel:
    """
    Dependency to enforce moderator access.

    This function:
    - Decodes the provided JWT access token.
    - Verifies if the token is valid and not expired.
    - Retrieves the user's group from the database.
    - Ensures the user belongs to the "MODERATOR" group.

    Raises:
        HTTPException (401): If the token is missing, invalid, or expired.
        HTTPException (403): If the user does not have moderator's privileges.

    Returns:
        UserGroupModel: The moderator group object if access is granted.
    """
    try:
        payload = jwt_manager.decode_access_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token!")

    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    stmt = select(UserGroupModel).filter(UserGroupModel.id == payload.get("group_id"))
    result = await db.execute(stmt)
    group = result.scalars().first()
    if not group:
        raise HTTPException(status_code=403, detail="Access forbidden: moderator or admin only")
    if group.name != UserGroupEnum.MODERATOR:
        raise HTTPException(status_code=403, detail="Access forbidden: moderator or admin only")

    return group
