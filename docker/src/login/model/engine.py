import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('postgresql://{}:{}@{}:5432/{}'.format(
    os.environ['LOGIN_DB_USER'],
    os.environ['LOGIN_DB_PASSWORD'],
    os.environ['LOGIN_DB_HOST'],
    os.environ['LOGIN_DB_NAME']
), echo=True)

Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
