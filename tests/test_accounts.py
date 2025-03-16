import logging
from colorsys import rgb_to_hls
from datetime import timezone, datetime
from unittest.mock import patch

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database import ActivationTokenModel, SessionLocal, UserModel, RefreshTokenModel, UserGroupEnum, UserGroupModel
from main import app

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000/api/v1/"
async_client = AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL)


@pytest.mark.asyncio
async def test_read_main():
    response = await async_client.get("theater/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, CineStreamX!"}


@pytest.mark.asyncio
async def register_user(
        db_session: SessionLocal,
        email: str = "test@email.com",
        password: str = "StrongPassword123!"
):
    await async_client.post("accounts/register/", json={"email": email, "password": password})
    stmt_user = select(UserModel).where(UserModel.email == email)
    result = await db_session.execute(stmt_user)
    user = result.scalars().first()
    return user


@pytest.mark.asyncio
async def get_user_group(db_session):
    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()

    if user_group is None:
        user_group = UserGroupModel(name=UserGroupEnum.USER)
        db_session.add(user_group)
        await db_session.commit()
    return user_group


@pytest.mark.asyncio
async def test_register_user_success(db_session):
    payload = {"email": "emailtest@example.com", "password": "StrongPassword123!"}
    response = await async_client.post("accounts/register/", json=payload)
    response_data = response.json()
    assert (
            response_data["email"] == "emailtest@example.com"
    ), "Returned email does not match."
    assert "id" in response_data, "Response does not contain user ID."
    assert response.status_code == 201, "Expected status code 201 Created."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    created_user = result.scalars().first()
    assert created_user.is_active is False, "Newly created user ia not active"


@pytest.mark.asyncio
async def test_register_user_failed_duplicate():
    """
    Test user registration conflict.
    Ensures that trying to register a user with an existing email
    returns a 409 Conflict status and the correct error message.
    """
    payload = {"email": "test@example.com", "password": "StrongPassword123!"}

    first_response = await async_client.post("accounts/register/", json=payload)
    assert first_response.status_code == 201, "Expected status code 201 Created."

    second_response = await async_client.post("accounts/register/", json=payload)
    assert second_response.status_code == 409, "Expected status code 409 Conflict."
    expected_message = f"A user with this email {payload['email']} already exists."
    response_data = second_response.json()
    assert (
            response_data["detail"] == expected_message
    ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_password, expected_error",
    [
        ("short", "Password must contain at least 8 characters."),
        ("NoDigitHere!", "Password must contain at least one digit."),
        ("nodigitnorupper@", "Password must contain at least one uppercase letter."),
        ("NOLOWERCASE1@", "Password must contain at least one lower letter."),
        (
                "NoSpecial123",
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &.",
        ),
    ],
)
async def test_register_user_password_validation(invalid_password, expected_error):
    """
    Test password strength validation in the user registration endpoint.
    Ensures that when an invalid password is provided, the endpoint returns the appropriate
    error message and a 422 status code.
    Args:
        invalid_password (str): The password to test.
        expected_error (str): The expected error message substring.
    """
    payload = {"email": "testuser@example.com", "password": invalid_password}
    response = await async_client.post("accounts/register/", json=payload)
    assert response.status_code == 422, "Expected status code 422 for invalid input."

    response_data = response.json()
    assert expected_error in str(
        response_data
    ), f"Expected error message: {expected_error}"


@pytest.mark.asyncio
async def test_register_user_internal_server_error():
    """
    Test server error during user registration.

    Ensures that a 500 Internal Server Error is returned when a database operation fails.

    This test patches the commit method of the AsyncSession to simulate a SQLAlchemyError,
    then verifies that the registration endpoint returns the appropriate HTTP 500 error
    with the expected error message.
    """
    payload = {"email": "erroruser@example.com", "password": "StrongPassword123!"}

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await async_client.post("accounts/register/", json=payload)

        assert (
                response.status_code == 500
        ), "Expected status code 500 for internal server error."

        response_data = response.json()
        expected_message = "An error occurred during user creation."
        assert (
                response_data["detail"] == expected_message
        ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_activation_token_created(db_session):
    """
    Test activation token was created and saved in DB.
    """
    payload = {"email": "test@example.com", "password": "StrongPassword123!"}
    response = await async_client.post("accounts/register/", json=payload)
    assert response.status_code == 201, "Expected status code 201 Created."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    created_user = result.scalars().first()

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == created_user.id
    )
    result = await db_session.execute(stmt_token)
    activation_token = result.scalars().first()

    assert activation_token.user_id == created_user.id, "Activation token and user id does not match."
    assert activation_token is not None, "Activation token is not None."
    assert activation_token.token is not None, "Activation token has no token value."


@pytest.mark.asyncio
async def test_request_activation_token_success(db_session):
    payload = {"email": "test@example.com", "password": "StrongPassword123!"}
    registration_response = await async_client.post("accounts/register/", json=payload)
    assert registration_response.status_code == 201, "Expected status code 201 Created."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    user = result.scalars().first()

    response_token = await async_client.post(
        "accounts/activate/",
        json={"email": user.email}
    )

    stmt_activation_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db_session.execute(stmt_activation_token)
    activation_token = result.scalars().first()

    assert activation_token.user_id == user.id, "Activation token and user id does not match."
    assert activation_token is not None, "Activation token is not None."
    assert activation_token.token is not None, "Activation token has no token value."

    expires_at = activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(timezone.utc), "Activation token is already expired."

    assert response_token.status_code == 200, "Expected status code 200 Ok."
    response_data = response_token.json()
    expected_message = "If you are registered, you will receive an email with instructions."
    assert (
            response_data["message"] == expected_message
    ), f"Expected message: {expected_message}"


@pytest.mark.asyncio
async def test_request_activation_token_but_account_already_active(db_session):
    payload = {"email": "test@example.com", "password": "StrongPassword123!"}
    registration_response = await async_client.post("accounts/register/", json=payload)
    assert registration_response.status_code == 201, "Expected status code 201 Created."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    user = result.scalars().first()
    user.is_active = True
    await db_session.commit()

    response = await async_client.post(
        "accounts/activate/",
        json={"email": user.email}
    )
    assert response.status_code == 400, "Expected status code 400 Bad request."
    response_data = response.json()
    expected_message = "Account is already active."
    assert (
            response_data["detail"] == expected_message
    ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_wrong_email_while_requesting_activation_token(db_session):
    response = await async_client.post(
        "accounts/activate/",
        json={"email": "wrongemail@example.com"}
    )
    assert response.status_code == 404, "Expected status code 404 Not found."
    response_data = response.json()
    expected_message = "A user with this email not found."
    assert (
            response_data["detail"] == expected_message
    ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_activation_complete_success(db_session):
    payload = {"email": "test@example.com", "password": "StrongPassword123!"}
    registration_response = await async_client.post("accounts/register/", json=payload)
    assert registration_response.status_code == 201, "Expected status code 201 Created."

    stmt_user = select(UserModel).where(UserModel.email == payload["email"])
    result = await db_session.execute(stmt_user)
    user = result.scalars().first()

    stmt_activation_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db_session.execute(stmt_activation_token)
    activation_token = result.scalars().first()

    response_token = await async_client.post(
        "accounts/activate-complete/",
        json={"email": user.email, "token": activation_token.token}
    )

    response_data = response_token.json()
    assert response_data["message"] == "Account was successfully activated!"

    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db_session.execute(stmt)
    empty_activation_token = result.scalars().first()
    assert empty_activation_token is None, "Activation token should be removed after success activation."


@pytest.mark.asyncio
async def test_login_success(db_session):
    """Test user login with registered credentials."""
    email = "test@example.com"
    password = "StrongPassword123!"

    user = await register_user(db_session, email, password)

    user.is_active = True
    await db_session.commit()

    login_response = await async_client.post(
        "accounts/login/",
        json={"email": email, "password": password}
    )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
    result = await db_session.execute(stmt)
    jwt_refresh_token = result.scalars().first()
    assert jwt_refresh_token.token is not None, "Refresh token has no token value."

    response_data = login_response.json()
    assert login_response.status_code == 201, "Expected status code 201 Created."
    assert "access_token" in response_data
    assert "refresh_token" in response_data
    assert response_data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_account_is_not_active(db_session):
    """Test user login with registered credentials, account is not active."""
    email = "test@example.com"
    password = "StrongPassword123!"
    await register_user(db_session, email, password)

    login_response = await async_client.post(
        "accounts/login/",
        json={"email": email, "password": password}
    )
    response_data = login_response.json()
    expected_error = "User account is not activated."
    assert login_response.status_code == 403, "User is not active, expected status 403 Forbidden."
    assert response_data["detail"] == expected_error


@pytest.mark.asyncio
async def test_login_user_invalid_cases(db_session):
    """
    Test login with invalid cases:
    1. Non-existent user.
    2. Incorrect password for an existing user.
    """
    login_payload = {
        "email": "nonexistent@example.com",
        "password": "SomePassword123!"
    }
    response = await async_client.post(
        "accounts/login/",
        json=login_payload
    )
    assert response.status_code == 401, "Expected status code 401 for non-existent user."
    assert response.json()["detail"] == "Invalid email or password.", \
        "Unexpected error message for non-existent user."

    user = await register_user(db_session)

    login_payload_incorrect_password = {
        "email": user.email,
        "password": "WrongPassword123!"
    }
    response = await async_client.post(
        "accounts/login/",
        json=login_payload_incorrect_password
    )
    assert response.status_code == 401, "Expected status code 401 for incorrect password."
    assert response.json()["detail"] == "Invalid email or password.", \
        "Unexpected error message for incorrect password."


@pytest.mark.asyncio
async def test_login_user_commit_error(db_session):
    """
    Test login when a database commit error occurs.
    Validates that the endpoint returns a 500 status code and an appropriate error message.
    """
    user_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!"
    }
    user_group = await get_user_group(db_session)
    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"]
    }

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await async_client.post("accounts/login/", json=login_payload)

    assert response.status_code == 500, "Expected status code 500 for database commit error."
    assert response.json()["detail"] == "An error occurred while processing the request.", (
        "Unexpected error message for database commit error."
    )
