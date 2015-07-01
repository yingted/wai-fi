from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String

Base = declarative_base()

class Device(Base):
	__tablename__ = 'devices'
	mac = Column(String, primary_key=True)
	overlay_dir = Column(String)
