import os
from celery import Celery

_base = os.getenv('REDIS_URL', 'redis://redis:6379')
BROKER_URL  = _base.rstrip('/0123456789') + '/0'
BACKEND_URL = _base.rstrip('/0123456789') + '/1'

celery_app = Celery(
    'scanner',
    broker=BROKER_URL,
    backend=BACKEND_URL,
    include=['app.tasks.scan_tasks'],
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    broker_connection_retry_on_startup=True,
)
