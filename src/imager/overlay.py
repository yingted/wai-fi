import contextlib
import os.path
import tempfile
import shutil
import sqlalchemy
import gen_misc
import subprocess
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import exists
from models import Base, Device

data_dir = 'data/pki'
db_path = os.path.join(data_dir, 'index.db')

def make_data_dir():
	try:
		os.makedirs(data_dir)
	except:
		pass

_engine = None
def get_engine():
	global _engine
	if _engine is None:
		make_data_dir()
		engine = create_engine('sqlite:///%s' % db_path, echo=True)
		Base.metadata.create_all(engine)
		_engine = engine
	return _engine

_Session = None
def get_Session():
	global _Session
	if _Session is None:
		Session = sessionmaker(bind=get_engine())
		_Session = Session
	return _Session

overlay_file_names = 'default_private_key', 'default_certificate', 'default_private_key.c', 'default_certificate.c'

@contextlib.contextmanager
def overlay_applied(overlay_dir, user_dir):
	backups = {}
	backup_dir = tempfile.mkdtemp(dir=user_dir)
	for name in overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		if os.path.exists(displaced_path):
			backup_path = os.path.join(backup_dir, name)
			shutil.copyfile(displaced_path, backup_path)
			backups[displaced_path] = backup_path
	for name in overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		overlay_path = os.path.join(overlay_dir, name)
		if os.path.exists(overlay_path):
			shutil.copyfile(overlay_path, displaced_path)
	subprocess.check_call(('make', '-C', user_dir) + overlay_file_names)
	try:
		yield
	finally:
		for displaced_path, backup_path in backups.iteritems():
			os.rename(backup_path, displaced_path)
		os.rmdir(backup_dir)
	for name in overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		overlay_path = os.path.join(overlay_dir, name)
		shutil.copyfile(displaced_path, overlay_path)

@contextlib.contextmanager
def get_overlay_dir(mac, port):
	session = get_Session()()
	try:
		overlay_dir = tempfile.mkdtemp(prefix='%s.' % mac, dir=data_dir)
		device = session.query(Device).filter(Device.mac == mac).first()
		if device is None:
			device = Device(mac=mac, overlay_dir=overlay_dir)
			session.add(device)
			try:
				yield overlay_dir
			except:
				shutil.rmtree(overlay_dir)
				session.rollback()
				raise # hopefully nothing threw
			else:
				session.commit()
		else:
			os.rmdir(overlay_dir)
			yield device.overlay_dir
	finally:
		session.close()
