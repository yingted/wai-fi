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
import config
import random

data_dir = config.data_dir

def make_data_dir():
	try:
		os.makedirs(data_dir)
	except:
		pass

cert_req_name = 'cert_req.txt'
device_id_name = 'icmp_net_device_id.txt'
overlay_file_names = 'default_private_key', 'default_certificate', 'default_private_key.c', 'default_certificate.c', cert_req_name, device_id_name

@contextlib.contextmanager
def overlay_applied(overlay_dir, user_dir):
	backups = {}
	backup_dir = tempfile.mkdtemp(dir=user_dir)
	try:
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
			else:
				try:
					os.remove(displaced_path)
				except OSError:
					pass # already removed

		subprocess.check_call(('make', '-C', user_dir, 'CC=true') + overlay_file_names)
		yield
	finally:
		for displaced_path, backup_path in backups.iteritems():
			os.rename(backup_path, displaced_path)
		shutil.rmtree(backup_dir)
	for name in overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		overlay_path = os.path.join(overlay_dir, name)
		shutil.copyfile(displaced_path, overlay_path)

def seed_overlay(overlay_dir, mac, device_id):
	with open(os.path.join(overlay_dir, cert_req_name), 'w') as f:
		f.write('''\
.
.
.
.
.
%(mac)s.device.ssl
.



''' % locals())
	with open(os.path.join(overlay_dir, device_id_name), 'w') as f:
		print >> f, device_id

@contextlib.contextmanager
def get_overlay_dir(mac, port):
	session = config.sql_Session()
	overlay_dir = None
	try:
		overlay_dir = tempfile.mkdtemp(prefix='%s.' % mac, dir=data_dir)
		device = session.query(Device).filter(Device.mac == mac).first()
		if device is None:
			while True:
				device_id = random.randrange(2**16)
				if not session.query(
						session.query(Device).filter(Device.id == device_id).exists()
					).scalar():
					break

			seed_overlay(overlay_dir=overlay_dir, mac=mac, device_id=device_id)
			device = Device(mac=mac, overlay_dir=overlay_dir, id=device_id)
			try:
				# Could conflict due to unique constraint
				session.add(device)
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
	except Exception as e:
		if overlay_dir is not None:
			try:
				shutil.rmtree(overlay_dir)
			except OSError:
				pass # already gone
		raise e
	finally:
		session.close()
