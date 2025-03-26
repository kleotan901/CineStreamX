import logging
from datetime import timezone, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database import (
    ActivationTokenModel,
    SessionLocal,
    UserModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
)
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
    password: str = "StrongPassword123!",
):
    await async_client.post(
        "accounts/register/", json={"email": email, "password": password}
    )
    stmt_user = select(UserModel).where(UserModel.email == email)
    result = await db_session.execute(stmt_user)
    user = result.scalars().first()
    return user


@pytest.mark.asyncio
async def login_user(
    db_session: SessionLocal,
    email: str = "test@email.com",
    password: str = "StrongPassword123!",
):
    user = await register_user(db_session=db_session, email=email, password=password)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {"email": email, "password": password}
    login_response = await async_client.post("accounts/login/", json=login_payload)
    return login_response


@pytest.mark.asyncio
async def login_user_with_admin_role(
    seed_user_groups,
    db_session: SessionLocal,
    email: str = "admin@email.com",
    password: str = "StrongPassword123!",
):
    await register_user(db_session=db_session, email=email)

    stmt = select(UserModel).where(UserModel.email == email)
    result = await db_session.execute(stmt)
    admin = result.scalars().first()
    admin.group_id = 3
    admin.is_active = True
    await db_session.commit()

    login_payload = {"email": email, "password": password}
    login_admin_response = await async_client.post(
        "accounts/login/", json=login_payload
    )
    return login_admin_response


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

    assert (
        activation_token.user_id == created_user.id
    ), "Activation token and user id does not match."
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
        "accounts/activate/", json={"email": user.email}
    )

    stmt_activation_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    result = await db_session.execute(stmt_activation_token)
    activation_token = result.scalars().first()

    assert (
        activation_token.user_id == user.id
    ), "Activation token and user id does not match."
    assert activation_token is not None, "Activation token is not None."
    assert activation_token.token is not None, "Activation token has no token value."

    expires_at = activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at > datetime.now(
        timezone.utc
    ), "Activation token is already expired."

    assert response_token.status_code == 200, "Expected status code 200 Ok."
    response_data = response_token.json()
    expected_message = (
        "If you are registered, you will receive an email with instructions."
    )
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

    response = await async_client.post("accounts/activate/", json={"email": user.email})
    assert response.status_code == 400, "Expected status code 400 Bad request."
    response_data = response.json()
    expected_message = "Account is already active."
    assert (
        response_data["detail"] == expected_message
    ), f"Expected error message: {expected_message}"


@pytest.mark.asyncio
async def test_wrong_email_while_requesting_activation_token(db_session):
    response = await async_client.post(
        "accounts/activate/", json={"email": "wrongemail@example.com"}
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

    stmt_activation_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    result = await db_session.execute(stmt_activation_token)
    activation_token = result.scalars().first()

    response_token = await async_client.post(
        "accounts/activate-complete/",
        json={"email": user.email, "token": activation_token.token},
    )

    response_data = response_token.json()
    assert response_data["message"] == "Account was successfully activated!"

    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db_session.execute(stmt)
    empty_activation_token = result.scalars().first()
    assert (
        empty_activation_token is None
    ), "Activation token should be removed after success activation."


@pytest.mark.asyncio
async def test_login_success(db_session):
    """Test user login with registered credentials."""
    email = "test@example.com"
    password = "StrongPassword123!"

    user = await register_user(db_session, email, password)

    user.is_active = True
    await db_session.commit()

    login_response = await async_client.post(
        "accounts/login/", json={"email": email, "password": password}
    )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
    result = await db_session.execute(stmt)
    jwt_refresh_token = result.scalars().first()
    assert jwt_refresh_token.token is not None, "Refresh token has token value in DB."

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
        "accounts/login/", json={"email": email, "password": password}
    )
    response_data = login_response.json()
    expected_error = "User account is not activated."
    assert (
        login_response.status_code == 403
    ), "User is not active, expected status 403 Forbidden."
    assert response_data["detail"] == expected_error


@pytest.mark.asyncio
async def test_login_user_invalid_cases(db_session):
    """
    Test login with invalid cases:
    1. Non-existent user.
    2. Incorrect password for an existing user.
    """
    login_payload = {"email": "nonexistent@example.com", "password": "SomePassword123!"}
    response = await async_client.post("accounts/login/", json=login_payload)
    assert (
        response.status_code == 401
    ), "Expected status code 401 for non-existent user."
    assert (
        response.json()["detail"] == "Invalid email or password."
    ), "Unexpected error message for non-existent user."

    user = await register_user(db_session)

    login_payload_incorrect_password = {
        "email": user.email,
        "password": "WrongPassword123!",
    }
    response = await async_client.post(
        "accounts/login/", json=login_payload_incorrect_password
    )
    assert (
        response.status_code == 401
    ), "Expected status code 401 for incorrect password."
    assert (
        response.json()["detail"] == "Invalid email or password."
    ), "Unexpected error message for incorrect password."


@pytest.mark.asyncio
async def test_login_user_commit_error(db_session, seed_user_groups):
    """
    Test login when a database commit error occurs.
    Validates that the endpoint returns a 500 status code and an appropriate error message.
    """
    user_payload = {"email": "testuser@example.com", "password": "StrongPassword123!"}

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db_session.execute(stmt)
    user_group = result.scalars().first()

    assert user_group is not None, "Default user group should exist."

    user = UserModel.create(
        email=user_payload["email"],
        raw_password=user_payload["password"],
        group_id=user_group.id,
    )
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {
        "email": user_payload["email"],
        "password": user_payload["password"],
    }

    with patch("routes.accounts.AsyncSession.commit", side_effect=SQLAlchemyError):
        response = await async_client.post("accounts/login/", json=login_payload)

    assert (
        response.status_code == 500
    ), "Expected status code 500 for database commit error."
    assert (
        response.json()["detail"] == "An error occurred while processing the request."
    ), "Unexpected error message for database commit error."


@pytest.mark.asyncio
async def test_refresh_access_token_success(db_session, jwt_manager):
    """
    Test successful access token refresh.

    Validates that a new access token is returned when a valid refresh token is provided.
    Steps:
    - Create an active user in the database.
    - Log in the user to obtain a refresh token.
    - Use the refresh token to obtain a new access token.
    - Verify that the new access token contains the correct user ID.
    """
    user = await register_user(db_session)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    login_payload = {"email": "test@email.com", "password": "StrongPassword123!"}
    login_response = await async_client.post("accounts/login/", json=login_payload)
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."
    login_data = login_response.json()
    refresh_token = login_data["refresh_token"]

    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await async_client.post(
        "accounts/refresh/", json=refresh_payload
    )
    assert (
        refresh_response.status_code == 200
    ), "Expected status code 200 for successful token refresh."
    refresh_data = refresh_response.json()
    assert "access_token" in refresh_data, "Access token is missing in the response."
    assert refresh_data["access_token"], "Access token is empty."

    access_token_data = jwt_manager.decode_access_token(refresh_data["access_token"])
    assert (
        access_token_data["user_id"] == user.id
    ), "Access token does not contain correct user ID."


@pytest.mark.asyncio
async def test_refresh_access_token_expired_token(db_session, jwt_manager):
    """
    Test refresh token with expired token.

    Validates that a 400 status code and "Token has expired." message are returned
    when the refresh token is expired.
    """
    expired_token = jwt_manager.create_refresh_token(
        {"user_id": 1}, expires_delta=timedelta(days=-1)
    )

    refresh_payload = {"refresh_token": expired_token}
    refresh_response = await async_client.post(
        "accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 400
    ), "Expected status code 400 for expired token."
    assert (
        refresh_response.json()["detail"] == "Token has expired."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_refresh_access_token_token_not_found(db_session, jwt_manager):
    """
    Test refresh token when token is not found in the database.

    Validates that a 401 status code and 'Refresh token not found.' message
    are returned when the refresh token is not stored in the database.
    """
    refresh_token = jwt_manager.create_refresh_token({"user_id": 1})
    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await async_client.post(
        "accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 401
    ), "Expected status code 401 for token not found."
    assert (
        refresh_response.json()["detail"] == "Refresh token not found."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_refresh_access_token_user_not_found(db_session, jwt_manager):
    """
    Test refresh token when user ID inside the token does not exist in the database.

    Validates that a 404 status code and "User not found." message
    are returned when the user ID in the token is invalid.

    Steps:
    - Create a new active user.
    - Generate a refresh token with an invalid user ID.
    - Store the refresh token in the database.
    - Attempt to refresh the access token using the invalid refresh token.
    - Verify that the endpoint returns a 404 error with the expected message.
    """

    user = await register_user(db_session)
    user.is_active = True
    db_session.add(user)
    await db_session.commit()

    invalid_user_id = 9999
    refresh_token = jwt_manager.create_refresh_token({"user_id": invalid_user_id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=invalid_user_id, days_valid=7, token=refresh_token
    )
    db_session.add(refresh_token_record)
    await db_session.commit()

    refresh_payload = {"refresh_token": refresh_token}
    refresh_response = await async_client.post(
        "accounts/refresh/", json=refresh_payload
    )

    assert (
        refresh_response.status_code == 404
    ), "Expected status code 404 for non-existent user."
    assert (
        refresh_response.json()["detail"] == "User not found."
    ), "Unexpected error message."


@pytest.mark.asyncio
async def test_logout_success(db_session, jwt_manager):
    """
    Test successful logout and delete refresh token.

    Check if provided refresh token is valid.
    Steps:
    - Log in the user to obtain a refresh token.
    - Use the refresh token to logout.
    - Remove the refresh token from DB
    """
    login_response = await login_user(db_session=db_session)
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."

    logout_response = await async_client.post(
        "accounts/logout/",
        json={"refresh_token": login_response.json()["refresh_token"]},
    )

    logout_data = logout_response.json()
    assert logout_response.status_code == 200, "Expected status code 200 Ok."
    assert logout_data["message"] == "User logged out!", "Logged out message."

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.user_id == 1)
    result = await db_session.execute(stmt)
    deleted_token = result.scalars().first()
    # Remove refresh token from DB
    db_session.delete(deleted_token)
    await db_session.commit()

    assert deleted_token is None, "No refresh token in DB for user."


@pytest.mark.asyncio
async def test_change_password_success(db_session, jwt_manager):
    """
    Test successful change password by entering the old password and a new password.
    Steps:
    - Create an active user in the database.
    - Log in the user to obtain a access token.
    - Enter the old password and a new password.
    """
    login_response = await login_user(db_session=db_session, password="OldPassword123!")
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."

    change_password_payload = {
        "email": "test@email.com",
        "old_password": "OldPassword123!",
        "new_password": "NewPassword123!",
        "access_token": login_response.json()["access_token"],
    }
    change_password_response = await async_client.post(
        "accounts/change-password/", json=change_password_payload
    )
    expected_msg = "Password was changed successfully."
    assert (
        change_password_response.status_code == 200
    ), "Expected status code 200 for successful login."
    assert (
        change_password_response.json()["message"] == expected_msg
    ), f"Expected message {expected_msg}."


@pytest.mark.asyncio
async def test_change_password_expired_access_token(db_session, jwt_manager):
    """
    Test errors raise while changing the password.
    Check if access token expired.
    """

    login_response = await login_user(db_session=db_session, password="OldPassword123!")
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."

    expired_access_token = jwt_manager.create_access_token(
        {"user_id": 1}, expires_delta=timedelta(days=-1)
    )

    change_password_payload = {
        "email": "test@email.com",
        "old_password": "OldPassword123!",
        "new_password": "NewPassword123!",
        "access_token": expired_access_token,
    }
    change_password_response = await async_client.post(
        "accounts/change-password/", json=change_password_payload
    )
    expected_error = "Token has expired."
    assert (
        change_password_response.status_code == 400
    ), "Expected status code 400 for Bad request."
    assert (
        change_password_response.json()["detail"] == expected_error
    ), f"Expected error: {expected_error}."


@pytest.mark.asyncio
async def test_change_password_invalid_access_token(db_session, jwt_manager):
    """
    Test error handling when attempting to change a password with an invalid access token.
    **Test Steps:**
    1. Log in as `test@email.com` (valid credentials).
    2. Log in as `test2@email.com` (valid credentials) and obtain an access token.
    3. Attempt to change `test@email.com`'s password using `test2@email.com`'s access token.
    **Expected Result:**
    - The request should fail with **HTTP 400 Bad Request**.
    - The response should contain an error message: `"Invalid access token."`
    """
    login_response = await login_user(db_session=db_session, password="OldPassword123!")
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."

    login_response_2 = await login_user(
        db_session=db_session, email="test2@email.com", password="StrongPassword123!"
    )
    assert (
        login_response_2.status_code == 201
    ), "Expected status code 201 for successful login."
    payload = {
        "email": "test@email.com",
        "old_password": "OldPassword123!",
        "new_password": "NewPassword123!",
        "access_token": login_response_2.json()["access_token"],
    }

    response = await async_client.post("accounts/change-password/", json=payload)
    expected_error = "Invalid access token."
    assert response.status_code == 400, "Expected status code 400 for Bad request."
    assert (
        response.json()["detail"] == expected_error
    ), f"Expected error: {expected_error}."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_new_password, expected_error",
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
async def test_change_password_validation(
    db_session, invalid_new_password, expected_error, jwt_manager
):
    """
    Test password strength validation in the user change_password endpoint.
    Ensures that when an invalid password is provided, the endpoint returns the appropriate
    error message and a 422 status code.

        Args:
            db_session: Data base session connection.
            invalid_new_password (str): The password to test.
            expected_error (str): The expected error message substring.
    """
    login_response = await login_user(db_session=db_session, password="OldPassword123!")
    assert (
        login_response.status_code == 201
    ), "Expected status code 201 for successful login."

    change_password_payload = {
        "email": "test@email.com",
        "old_password": "OldPassword123!",
        "new_password": invalid_new_password,
        "access_token": login_response.json()["access_token"],
    }
    change_password_response = await async_client.post(
        "accounts/change-password/", json=change_password_payload
    )

    assert (
        change_password_response.status_code == 422
    ), "Expected status code 422 for invalid input."
    response_data = change_password_response.json()
    assert expected_error in str(
        response_data
    ), f"Expected error message: {expected_error}"


@pytest.mark.asyncio
async def test_update_user_data_by_admin_successfully(
    db_session, jwt_manager, seed_user_groups
):
    """
    Test update user's data by admin
    (change group memberships and manually activate accounts).

    **Test Steps:**
    1. Register a user in the database (user with ID 1).
    2. Register and log in as an admin user.
    3. Attempt to update user 1's data by sending a request to the
       'accounts/1/manage-user/' endpoint with the admin's access token.

    **Expected Result:**
    - The request should be **success** (HTTP 200) since only admins
      are allowed to manage user data.
    """
    await register_user(db_session=db_session)
    login_admin_response = await login_user_with_admin_role(
        seed_user_groups=seed_user_groups, db_session=db_session
    )
    assert (
        login_admin_response.status_code == 201
    ), "Expected status code 201 for successful login."

    admin_access_token = login_admin_response.json()["access_token"]
    update_payload = {
        "is_active": True,
        "group": "MODERATOR",
    }

    response = await async_client.put(
        "accounts/1/manage-user/",
        json=update_payload,
        headers={"Authorization": f"Bearer {admin_access_token}"},
    )

    decoded_access_data = jwt_manager.decode_access_token(admin_access_token)
    assert (
        decoded_access_data.get("group_id") == 3
    ), "Expect group_id is 3 (user with ADMIN role)"

    stmt_usr = select(UserModel).where(UserModel.id == 1)
    result = await db_session.execute(stmt_usr)
    db_user = result.scalars().first()

    assert db_user.is_active is True
    assert db_user.group_id == 2
    assert (
        response.status_code == 200
    ), "Expect status 200, user's data was updated successfully"


@pytest.mark.asyncio
async def test_forbid_access_to_change_users_data_by_not_admin(db_session, jwt_manager):
    """
    Test to ensure that only ADMIN users can manage user data
    (change group memberships and manually activate accounts).

    **Test Steps:**
    1. Register a user in the database (user with ID 1).
    2. Register and log in as a non-admin user.
    3. Attempt to update user 1's data by sending a request to the
       'accounts/1/manage-user/' endpoint with the non-admin's access token.

    **Expected Result:**
    - The request should be **forbidden** (HTTP 403) since only admins
      are allowed to manage user data.
    """
    await register_user(db_session=db_session)

    login_not_admin_response = await login_user(
        db_session=db_session, email="notadmin@email.com"
    )
    assert (
        login_not_admin_response.status_code == 201
    ), "Expected status code 201 for successful login."

    not_admin_access_token = login_not_admin_response.json()["access_token"]

    update_payload = {
        "is_active": True,
        "group": "MODERATOR",
    }

    response = await async_client.put(
        "accounts/1/manage-user/",
        json=update_payload,
        headers={"Authorization": f"Bearer {not_admin_access_token}"},
    )

    assert (
        response.status_code == 403
    ), "Expect status 403, Forbidden access, admin only"
