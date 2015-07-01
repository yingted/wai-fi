import contextlib
import os.path
import tempfile
import shutil
import sqlalchemy
import models
import gen_misc
import subprocess

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
		shutil.copyfile(overlay_path, displaced_path)
	subprocess.check_call(('make', '-C', user_dir) + overlay_file_names)
	try:
		yield
	else:
		for name in overlay_file_names:
			displaced_path = os.path.join(user_dir, name)
			overlay_path = os.path.join(overlay_dir, name)
			shutil.copyfile(displaced_path, overlay_path)
	finally:
		for displaced_path, backup_path in backups.iteritems():
			os.rename(backup_path, displaced_path)
		os.rmdir(backup_dir)

@contextlib.contextmanager
def get_overlay_dir(mac_str, port):
	with ...open db transaction:
		overlay_dir = tempfile.mkdtemp(prefix='%s.' % macstr, dir='/tmp')
		if ...INSERT overlay_dir ON CONFLICT IGNORE:
			try:
				yield overlay_dir
			except:
				shutil.rmtree(overlay_dir)
				raise # hopefully rmtree doesn't throw
			else:
				...commit overlay_dir to db
		else:
			os.rmdir(overlay_dir)
			yield old_overlay_dir
