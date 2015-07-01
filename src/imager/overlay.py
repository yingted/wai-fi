import contextlib
import os.path
import tempfile
import shutil
import sqlalchemy
import models
import gen_misc

overlay_file_names = 'default_private_key', 'default_certificate', 'default_private_key.c', 'default_certificate.c'

@contextlib.contextmanager
def get_overlay_dir(mac_str, port):
	with ...open db transaction:
		overlay_dir = tempfile.mkdtemp(prefix='%s.' % macstr, dir='/tmp')
		if ...INSERT overlay_dir ON CONFLICT IGNORE:
			...populate overlay_dir
			try:
				yield overlay_dir
			except Exception:
				shutil.rmtree(overlay_dir)
				raise # hopefully rmtree doesn't throw
			else:
				...commit overlay_dir to db
		else:
			os.rmdir(overlay_dir)
			yield old_overlay_dir
