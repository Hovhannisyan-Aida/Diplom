from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
import time
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

# Retry connection to database
max_retries = 5
retry_delay = 5  # seconds

for attempt in range(max_retries):
    try:
        engine = create_engine(settings.DATABASE_URL)
        # Test connection
        with engine.connect() as conn:
            logger.info("Database connection successful")
        break
    except OperationalError as e:
        if attempt < max_retries - 1:
            logger.warning(f"Database connection failed (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
        else:
            logger.error(f"Could not connect to database after {max_retries} attempts")
            raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()