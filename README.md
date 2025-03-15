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