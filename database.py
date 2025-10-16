import os
from dotenv import load_dotenv
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv()  
USER = os.getenv("user")
PASSWORD = os.getenv("password")
HOST = os.getenv("host")
PORT = os.getenv("port")
DBNAME = os.getenv("dbname")
if not all([USER, PASSWORD, HOST, PORT, DBNAME]):
    raise ValueError("One or more environment variables are not set. Please check your .env file.")
     
DATABASE_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DBNAME}?sslmode=require"
    
engine = create_engine(DATABASE_URL)
    
Base = declarative_base()

try:
    with engine.connect():
        print("Connection to Supabase successful!")
except Exception as e:
         print(f"Failed to connect: {e}")
     
from sqlalchemy.ext.declarative import declarative_base

class Offense(Base):
    __tablename__ = 'offenses'
    
    id = Column(Integer, primary_key=True, index=True)
    user_principal_name = Column(String, index=True)
    incident_title = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Create a session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_db_and_tables():
    """
    Initialize the database and create the tables if they don't exist.
    """
    Base.metadata.create_all(bind=engine)

def log_offense(db, user_upn, title):
    """
    Add a new offense record to the database.
    
    :param db: SQLAlchemy session object
    :param user_upn: The user's principal name (string)
    :param title: The incident title (string)
    """
    new_offense = Offense(user_principal_name=user_upn, incident_title=title)
    db.add(new_offense)
    db.commit()
    db.refresh(new_offense)  # Refresh to get any auto-generated values

def get_offense_count(db, user_upn):
    """
    Get the count of previous offenses for a given user.
    
    :param db: SQLAlchemy session object
    :param user_upn: The user's principal name (string)
    :return: Integer count of offenses
    """
    return db.query(Offense).filter(Offense.user_principal_name == user_upn).count()
