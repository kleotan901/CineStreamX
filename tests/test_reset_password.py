import logging
from datetime import timezone, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError

from database import UserModel, PasswordResetTokenModel, ActivationTokenModel

from main import app

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000/api/v1/"
async_client = AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL)


@pytest.mark.asyncio
async def test_request_password_reset_token_success(db_session):
    """
    Test successful password reset token request.

    Ensures that a password reset token is created for an active user.

    Steps:
    - Register a new user.
    - Mark the user as active.
    - Request a password reset token.
    - Verify that the endpoint returns status 200 and the expected success message.
    - Query the database to confirm that a PasswordResetTokenModel record was created.
    - Verify that the token's expiration date is in the future.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await async_client.post(
        "accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_payload = {"email": registration_payload["email"]}
    reset_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_payload
    )
    assert (
        reset_response.status_code == 200
    ), "Expected status code 200 for successful token request."
    assert (
        reset_response.json()["message"]
        == "If you are registered, you will receive an email with instructions."
    ), "Expected success message for password reset token request."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    reset_token = result_token.scalars().first()
    assert (
        reset_token is not None
    ), "Password reset token should be created for the user."

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(
        timezone.utc
    ), "Password reset token should have a future expiration date."


@pytest.mark.asyncio
async def test_request_password_reset_token_nonexistent_user(db_session):
    """
    Test password reset token request for a non-existent user.

    Ensures that the endpoint responds with a generic success message and that no password reset token is created
    when the email does not exist in the database.
    """
    reset_payload = {"email": "nonexistent@example.com"}

    reset_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_payload
    )
    assert (
        reset_response.status_code == 200
    ), "Expected status code 200 for non-existent user request."
    assert (
        reset_response.json()["message"]
        == "If you are registered, you will receive an email with instructions."
    ), "Expected generic success message for non-existent user request."

    stmt = select(func.count(PasswordResetTokenModel.id))
    result = await db_session.execute(stmt)
    reset_token_count = result.scalar_one()
    assert (
        reset_token_count == 0
    ), "No password reset token should be created for non-existent user."


@pytest.mark.asyncio
async def test_request_password_reset_token_for_inactive_user(db_session):
    """
    Test password reset token request for a registered but inactive user.

    Ensures that the endpoint returns the generic success message and that no password reset token
    is created when the user is registered but inactive.
    """
    registration_payload = {
        "email": "inactiveuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await async_client.post(
        "accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    created_user = result.scalars().first()
    assert created_user is not None, "User should be created in the database."
    assert not created_user.is_active, "User should not be active after registration."

    reset_payload = {"email": registration_payload["email"]}
    reset_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_payload
    )
    assert (
        reset_response.status_code == 200
    ), "Expected status code 200 for inactive user password reset request."
    assert (
        reset_response.json()["message"]
        == "If you are registered, you will receive an email with instructions."
    ), "Expected generic success message for inactive user password reset request."

    stmt_tokens = select(func.count(PasswordResetTokenModel.id))
    result_tokens = await db_session.execute(stmt_tokens)
    reset_token_count = result_tokens.scalar_one()
    assert (
        reset_token_count == 0
    ), "No password reset token should be created for an inactive user."


@pytest.mark.asyncio
async def test_reset_password_success(db_session):
    """
    Test the complete password reset flow.

    Steps:
    - Register a user.
    - Activate the user.
    - Request a password reset token.
    - Use the token to reset the password.
    - Verify the password is updated in the database.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "OldPassword123!",
    }
    registration_response = await async_client.post(
        "accounts/register/", json=registration_payload
    )
    assert (
        registration_response.status_code == 201
    ), "Expected status code 201 for successful registration."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    created_user = result.scalars().first()
    assert created_user is not None, "User should be created in the database."

    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == created_user.id
    )
    result_token = await db_session.execute(stmt_token)
    activation_token = result_token.scalars().first()
    assert (
        activation_token is not None
    ), "Activation token should be created in the database."

    activation_payload = {
        "email": registration_payload["email"],
        "token": activation_token.token,
    }
    activation_response = await async_client.post(
        "accounts/activate-complete/", json=activation_payload
    )
    assert (
        activation_response.status_code == 200
    ), "Expected status code 200 for successful activation."

    await db_session.refresh(created_user)
    assert created_user.is_active, "User should be active after successful activation."

    reset_request_payload = {"email": registration_payload["email"]}
    reset_request_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_request_payload
    )
    assert (
        reset_request_response.status_code == 200
    ), "Expected status code 200 for password reset token request."

    stmt_reset = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == created_user.id
    )
    result_reset = await db_session.execute(stmt_reset)
    reset_token_record = result_reset.scalars().first()
    assert (
        reset_token_record is not None
    ), "Password reset token should be created in the database."

    new_password = "NewSecurePassword123!"
    reset_payload = {
        "email": registration_payload["email"],
        "token": reset_token_record.token,
        "password": new_password,
    }
    reset_response = await async_client.post(
        "accounts/reset-password/complete/", json=reset_payload
    )
    assert (
        reset_response.status_code == 200
    ), "Expected status code 200 for successful password reset."
    assert (
        reset_response.json()["message"] == "Password reset successfully."
    ), "Unexpected response message for password reset."

    await db_session.refresh(created_user)
    assert created_user.verify_password(
        new_password
    ), "Password should be updated successfully in the database."


@pytest.mark.asyncio
async def test_reset_password_invalid_email(db_session):
    """
    Test password reset with an email that does not exist in the database.

    Validates that the endpoint returns a 400 status code and appropriate error message.
    """
    reset_payload = {
        "email": "nonexistent@example.com",
        "token": "random_token",
        "password": "NewSecurePassword123!",
    }

    response = await async_client.post(
        "accounts/reset-password/complete/", json=reset_payload
    )

    assert response.status_code == 400, "Expected status code 400 for invalid email."
    assert (
        response.json()["detail"] == "Invalid email or token."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_reset_password_invalid_token(db_session):
    """
    Test password reset with an incorrect token.

    Validates that the endpoint returns a 400 status code and an appropriate error message when an invalid token is provided.
    Also ensures that any invalid token is removed from the database.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    response = await async_client.post("accounts/register/", json=registration_payload)
    assert response.status_code == 201, "User registration failed."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_request_payload = {"email": registration_payload["email"]}
    response = await async_client.post(
        "accounts/password-reset/request/", json=reset_request_payload
    )
    assert response.status_code == 200, "Password reset request failed."

    reset_complete_payload = {
        "email": registration_payload["email"],
        "token": "incorrect_token",
        "password": "NewSecurePassword123!",
    }
    response = await async_client.post(
        "accounts/reset-password/complete/", json=reset_complete_payload
    )
    assert response.status_code == 400, "Expected status code 400 for invalid token."
    assert (
        response.json()["detail"] == "Invalid email or token."
    ), "Unexpected error message."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    token_record = result_token.scalars().first()
    assert token_record is None, "Invalid token was not removed."


@pytest.mark.asyncio
async def test_reset_password_expired_token(db_session):
    """
    Test password reset with an expired token.

    Validates that the endpoint returns a 400 status code and an appropriate error message when the password
    reset token is expired, and verifies that the expired token is removed from the database.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await async_client.post(
        "accounts/register/", json=registration_payload
    )
    assert registration_response.status_code == 201, "User registration failed."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_request_payload = {"email": registration_payload["email"]}
    reset_request_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_request_payload
    )
    assert reset_request_response.status_code == 200, "Password reset request failed."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    token_record = result_token.scalars().first()
    assert token_record is not None, "Password reset token not created."

    token_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db_session.commit()

    reset_complete_payload = {
        "email": registration_payload["email"],
        "token": token_record.token,
        "password": "NewSecurePassword123!",
    }
    reset_response = await async_client.post(
        "accounts/reset-password/complete/", json=reset_complete_payload
    )
    assert (
        reset_response.status_code == 400
    ), "Expected status code 400 for expired token."
    assert (
        reset_response.json()["detail"] == "Invalid email or token."
    ), "Unexpected error message."

    stmt_token_check = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token_check = await db_session.execute(stmt_token_check)
    expired_token = result_token_check.scalars().first()
    assert expired_token is None, "Expired token was not removed."


@pytest.mark.asyncio
async def test_reset_password_sqlalchemy_error(db_session):
    """
    Test password reset when a database commit raises SQLAlchemyError.

    Validates that the endpoint returns a 500 Internal Server Error and the appropriate error message
    when an error occurs during the password reset process.

    Steps:
    - Register a new user.
    - Mark the user as active.
    - Request a password reset token.
    - Attempt to reset the password while simulating a database commit error.
    - Verify that a 500 error is returned with the expected error message.
    """
    registration_payload = {
        "email": "testuser@example.com",
        "password": "StrongPassword123!",
    }
    registration_response = await async_client.post(
        "accounts/register/", json=registration_payload
    )
    assert registration_response.status_code == 201, "User registration failed."

    stmt = select(UserModel).where(UserModel.email == registration_payload["email"])
    result = await db_session.execute(stmt)
    user = result.scalars().first()
    assert user is not None, "User should exist in the database."

    user.is_active = True
    await db_session.commit()

    reset_request_payload = {"email": registration_payload["email"]}
    reset_request_response = await async_client.post(
        "accounts/password-reset/request/", json=reset_request_payload
    )
    assert reset_request_response.status_code == 200, "Password reset request failed."

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db_session.execute(stmt_token)
    token_record = result_token.scalars().first()
    assert token_record is not None, "Password reset token not created."

    reset_complete_payload = {
        "email": registration_payload["email"],
        "token": token_record.token,
        "password": "NewSecurePassword123!",
    }

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        reset_response = await async_client.post(
            "accounts/reset-password/complete/", json=reset_complete_payload
        )

    assert (
        reset_response.status_code == 500
    ), "Expected status code 500 for SQLAlchemyError."
    assert (
        reset_response.json()["detail"]
        == "An error occurred while resetting the password."
    ), "Unexpected error message for SQLAlchemyError."
