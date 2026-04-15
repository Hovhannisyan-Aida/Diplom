from app.db.base import Base
from app.db.session import engine
from app.models.user import User
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("✅ Tables created successfully!")