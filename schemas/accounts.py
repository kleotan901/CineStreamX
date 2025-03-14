from pydantic import BaseModel, EmailStr, field_validator
from database.validators.accounts import validate_password_strength


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str
    group_id: int = 1

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return value.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return validate_password_strength(value)

    model_config = {"from_attributes": True}


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {"from_attributes": True}


class ActivationTokenRequestSchema(UserBase):
    model_config = {"from_attributes": True}


class ActivationAccountCompleteSchema(UserBase):
    token: str
    model_config = {"from_attributes": True}

class MessageResponseSchema(BaseModel):
    message: str
