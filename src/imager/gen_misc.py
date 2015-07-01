import subprocess
import lockfile
import os.path
import re
import contextlib
import overlay
import shutil
import tempfile

app_dir = '../fw/esp_iot_sdk_v1.1.1/app'
user_dir = os.path.join(app_dir, user_dir)

@contextlib.contextmanager
def overlay_applied(overlay_dir, user_dir):
	backups = {}
	backup_dir = tempfile.mkdtemp(dir=user_dir)
	for name in overlay.overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		if os.path.exists(displaced_path):
			backup_path = os.path.join(backup_dir, name)
			shutil.copyfile(displaced_path, backup_path)
			backups[displaced_path] = backup_path
	for name in overlay.overlay_file_names:
		displaced_path = os.path.join(user_dir, name)
		overlay_path = os.path.join(overlay_dir, name)
		shutil.copyfile(overlay_path, displaced_path)
	try:
		yield
	finally:
		for displaced_path, backup_path in backups.iteritems():
			os.rename(backup_path, displaced_path)
		os.rmdir(backup_dir)

def call(overlay_dir):
	with lockfile.LockFile(app_dir), overlay_applied(overlay_dir, user_dir):
		gen_misc_path = os.path.join(app_dir, 'gen_misc.sh')
		p = subprocess.Popen(('bash', 'gen_misc.sh'), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		stdout, stderr = p.communicate()
		p.wait()

		paths = {}
		m = re.match(pattern=r'.*^Generate .* successully in folder (\S+)\.(.*)', string=stdout, flags=re.M)
		bin_dir, rest = m.groups()
		for m in re.finditer(r'^([^-]+)-+>(0x[0-9a-f]+)$', rest, flags=re.M):
			name, addr = m.groups()
			bin_path = os.path.join(app_dir, bin_dir, name)
			paths[addr] = bin_path
		return paths
