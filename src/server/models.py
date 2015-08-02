import collections
import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, BINARY, DateTime, String, ForeignKey
import config
import imager.models

Base = declarative_base()

class FromTupleMixin(object):
	@classmethod
	def from_tuple(clazz, fields):
		return clazz(**clazz.Tuple(*fields)._asdict())

_HeaderTuple = collections.namedtuple('_HeaderTuple', (
	'logging_device',
	'fc_type',
	'fc_flags',
	'dur',
	'addr1',
	'addr2',
	'addr3',
	'seqid',
	'rssi',
))

class Header(Base, FromTupleMixin):
	Tuple = _HeaderTuple
	__tablename__ = 'logged_headers'
	id = Column(Integer, primary_key=True)
	created_at = Column(DateTime, default=datetime.datetime.utcnow)
	logging_device = Column(String, ForeignKey('devices.mac'))
	fc_type = Column(Integer)
	fc_flags = Column(Integer)
	dur = Column(Integer)
	addr1 = Column(BINARY(6))
	addr2 = Column(BINARY(6))
	addr3 = Column(BINARY(6))
	seqid = Column(Integer)
	rssi = Column(Integer)

Base.metadata.create_all(config.sql_engine)
