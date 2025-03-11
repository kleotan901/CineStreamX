import logging
from unittest.mock import patch

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database import ActivationTokenModel, SessionLocal, UserModel
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
async def test_register_user_success():
    payload = {"email": "EmailTest@example.com", "password": "StrongPassword123!"}

    response = await async_client.post("accounts/register/", json=payload)
    response_data = response.json()
    assert (
        response_data["email"] == "emailtest@example.com"
    ), "Returned email does not match."
    assert "id" in response_data, "Response does not contain user ID."
    assert response.status_code == 201, "Expected status code 201 Created."


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
