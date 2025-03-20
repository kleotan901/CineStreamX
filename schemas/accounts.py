from pydantic import BaseModel, EmailStr, field_validator
from database.validators.accounts import validate_password_strength


class BaseEmailPasswordSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return value.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return validate_password_strength(value)

    model_config = {"from_attributes": True}


class UserRegistrationRequestSchema(BaseEmailPasswordSchema):
    group_id: int = 1


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class ActivationTokenRequestSchema(BaseModel):
    email: EmailStr
    model_config = {"from_attributes": True}


class ActivationAccountCompleteSchema(ActivationTokenRequestSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginRequestSchema(BaseEmailPasswordSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserLogoutRequestSchema(TokenRefreshRequestSchema):
    pass


class UserChangePasswordRequestSchema(BaseModel):
    email: EmailStr
    old_password: str
    new_password: str
    access_token: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value):
        return validate_password_strength(value)

    model_config = {"from_attributes": True}


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseEmailPasswordSchema):
    token: str
