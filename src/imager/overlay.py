import contextlib
import os
import tempfile
import shutil
import sqlite3

@contextlib.contextmanager
def get_overlay_dir(mac_str, port):
	overlay_dir = tempfile.mkdtemp(prefix='%s.' % macstr, dir='/tmp')
	...populate overlay_dir
	try:
		yield overlay_dir
	except Exception:
		shutil.rmtree(overlay_dir)
		raise # hopefully rmtree doesn't throw
	else:
		...commit overlay_dir to db
