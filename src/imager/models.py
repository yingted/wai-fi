from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String
import config

Base = declarative_base()

class Device(Base):
	__tablename__ = 'devices'
	mac = Column(String, primary_key=True)
	overlay_dir = Column(String)

Base.metadata.create_all(config.sql_engine)
