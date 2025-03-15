import logging
from datetime import datetime, timezone
from typing import cast

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from celery_app import celery_app
from database import ActivationTokenModel

logger = logging.getLogger(__name__)

# Synchronous DB session (for Celery)
DATABASE_URL = "sqlite:///./movies_db.db"
engine = create_engine(DATABASE_URL)
SyncSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@celery_app.task
def delete_expired_tokens():
    db: SyncSessionLocal = SyncSessionLocal()
    try:
        activation_tokens = db.query(ActivationTokenModel).all()
        now_utc = datetime.now(timezone.utc)
        for token in list(activation_tokens):
            if cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < now_utc:
                db.delete(token)
                db.commit()
                logger.info(f"Expired token {token} was deleted successfully!")
    except Exception as e:
        logger.error(f"Error deleting tokens: {e}")
    finally:
        db.close()
