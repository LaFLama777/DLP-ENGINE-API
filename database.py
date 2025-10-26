import os
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get database URL from environment
# Support both formats: full DATABASE_URL or individual components
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Build from components if DATABASE_URL not provided
    USER = os.getenv("user")
    PASSWORD = os.getenv("password")
    HOST = os.getenv("host")
    PORT = os.getenv("port", "5432")
    DBNAME = os.getenv("dbname")
    
    if all([USER, PASSWORD, HOST, DBNAME]):
        DATABASE_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DBNAME}?sslmode=require"
        logger.info("Database URL constructed from individual environment variables")
    else:
        # Fallback to SQLite for local development
        DATABASE_URL = "sqlite:///./dlp_offenses.db"
        logger.warning("Using SQLite fallback - set DATABASE_URL or Supabase credentials for production")

# Create engine based on database type
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
    logger.info("✓ Using SQLite database (local development)")
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,  # Verify connections before using
        pool_size=10,
        max_overflow=20
    )
    logger.info("✓ Using PostgreSQL database (Supabase)")

# Test database connection
#try:
 #   with engine.connect() as connection:
  #      connection.execute("SELECT 1")
   # logger.info("✓ Database connection successful!")
#except Exception as e:
 #   logger.error(f"✗ Database connection failed: {e}")
  #  raise

# Create base class for models
Base = declarative_base()

# Define Offense model
class Offense(Base):
    """Model for storing DLP offense records"""
    __tablename__ = 'offenses'
    
    id = Column(Integer, primary_key=True, index=True)
    user_principal_name = Column(String, index=True, nullable=False)
    incident_title = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Offense(id={self.id}, user={self.user_principal_name}, timestamp={self.timestamp})>"

# Create session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_db_and_tables():
    """
    Initialize the database and create tables if they don't exist.
    Safe to call multiple times - only creates tables that don't exist.
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✓ Database tables initialized")
    except Exception as e:
        logger.error(f"✗ Failed to create tables: {e}")
        raise

def log_offense(db, user_upn: str, title: str):
    """
    Add a new offense record to the database.
    
    Args:
        db: SQLAlchemy session object
        user_upn: The user's principal name (email)
        title: The incident title/description
        
    Returns:
        Offense: The created offense record
    """
    try:
        new_offense = Offense(
            user_principal_name=user_upn,
            incident_title=title
        )
        db.add(new_offense)
        db.commit()
        db.refresh(new_offense)
        logger.info(f"✓ Offense logged for user: {user_upn}")
        return new_offense
    except Exception as e:
        db.rollback()
        logger.error(f"✗ Failed to log offense: {e}")
        raise

def get_offense_count(db, user_upn: str) -> int:
    """
    Get the count of previous offenses for a given user.
    
    Args:
        db: SQLAlchemy session object
        user_upn: The user's principal name (email)
        
    Returns:
        int: Number of offenses for this user
    """
    try:
        count = db.query(Offense).filter(
            Offense.user_principal_name == user_upn
        ).count()
        logger.info(f"User {user_upn} has {count} previous offense(s)")
        return count
    except Exception as e:
        logger.error(f"✗ Failed to get offense count: {e}")
        return 0

def get_all_offenses(db, limit: int = 100, offset: int = 0):
    """
    Get all offenses with pagination.
    
    Args:
        db: SQLAlchemy session object
        limit: Maximum number of records to return
        offset: Number of records to skip
        
    Returns:
        list: List of Offense objects
    """
    try:
        offenses = db.query(Offense).order_by(
            Offense.timestamp.desc()
        ).limit(limit).offset(offset).all()
        return offenses
    except Exception as e:
        logger.error(f"✗ Failed to fetch offenses: {e}")
        return []

def get_user_offense_history(db, user_upn: str):
    """
    Get all offenses for a specific user.
    
    Args:
        db: SQLAlchemy session object
        user_upn: The user's principal name (email)
        
    Returns:
        list: List of Offense objects for this user
    """
    try:
        offenses = db.query(Offense).filter(
            Offense.user_principal_name == user_upn
        ).order_by(Offense.timestamp.desc()).all()
        return offenses
    except Exception as e:
        logger.error(f"✗ Failed to fetch user offense history: {e}")
        return []

def get_database_stats(db):
    """
    Get database statistics.
    
    Args:
        db: SQLAlchemy session object
        
    Returns:
        dict: Database statistics
    """
    try:
        total_offenses = db.query(Offense).count()
        unique_users = db.query(Offense.user_principal_name).distinct().count()
        
        # Get most recent offense
        latest_offense = db.query(Offense).order_by(
            Offense.timestamp.desc()
        ).first()
        
        return {
            "total_offenses": total_offenses,
            "unique_users": unique_users,
            "latest_offense_time": latest_offense.timestamp if latest_offense else None
        }
    except Exception as e:
        logger.error(f"✗ Failed to get database stats: {e}")
        return {
            "total_offenses": 0,
            "unique_users": 0,
            "latest_offense_time": None
        }

# Initialize database on import
if __name__ != "__main__":
    try:
        create_db_and_tables()
    except Exception as e:
        logger.error(f"Failed to initialize database on import: {e}")