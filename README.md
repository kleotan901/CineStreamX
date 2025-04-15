# CineStreamX (FastApi project)

An online cinema is a digital platform that allows users to select, watch, and purchase access to movies and other video materials via the internet. These services have become popular due to their convenience, a wide selection of content, and the ability to personalize the user experience.

### Run FastAPI server
+ cd CineStreamX
+ uvicorn main:app --reload

### Run tests:
PYTHONPATH=$(pwd) pytest

### Run CELERY
* redis-server
* celery -A celery_app worker --loglevel=info
* celery -A celery_app beat --loglevel=info

### Run MailHog test server for email sending
+ in root dir run  - ./commands/setup_mailhog_auth.sh - to create Auth file  with user: admin and hashed password.
+ run server MailHog with cmd - MailHog


##### `/schemas/`

Defines the data schemas using Pydantic for request validation and response models.

- **`__init__.py`**: Initializes the `schemas` module.
- **`accounts.py`**: Schemas for account-related operations.
- **`examples/`**: Contains example schemas used for documentation or testing.
  - **`__init__.py`**: Initializes the `examples` module.
  - **`movies.py`**: Example schemas for movie data.
- **`movies.py`**: Schemas for movie-related operations.
