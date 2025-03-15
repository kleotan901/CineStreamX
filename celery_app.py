import os

from celery.schedules import crontab
from celery import Celery
from config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    "worker",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["tasks"],
)

celery_app.conf.update(
    broker_url=CELERY_BROKER_URL,  # Ensure correct broker
    result_backend=CELERY_RESULT_BACKEND,
    timezone="UTC",
)

celery_app.conf.beat_schedule = {
    "run_delete_expired_tokens_every_24_hours": {
        "task": "tasks.delete_expired_tokens",
        "schedule": crontab(minute="0", hour="0"),  # Run every day at midnight (00:00)
    }
}

celery_app.conf.timezone = "UTC"
