from sqlalchemy import select
from sqlalchemy.orm import joinedload

from database import UserModel, ActivationTokenModel


async def get_user_by_email(email, db):
    stmt = select(UserModel).where(UserModel.email == email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()
    return existing_user


async def create_user(user_data, db):
    new_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_data.group_id,
    )
    db.add(new_user)
    await db.flush()
    return new_user


async def get_activation_token(data, db):
    stmt_token = (
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == data.email,
            ActivationTokenModel.token == data.token
        )
    )
    result = await db.execute(stmt_token)
    token_record = result.scalars().first()
    return token_record


async def create_activation_token(user, db):
    activation_token = ActivationTokenModel(user_id=user.id)
    db.add(activation_token)
    await db.commit()
    await db.refresh(activation_token)
    return activation_token


async def delete_activation_token(token, db):
    await db.delete(token)
    await db.commit()
