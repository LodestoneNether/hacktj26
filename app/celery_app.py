from celery import Celery

from app.config import settings

celery = Celery('osint', broker=settings.celery_broker_url, backend=settings.celery_result_backend)
celery.conf.task_always_eager = settings.celery_task_always_eager
celery.conf.task_eager_propagates = True
