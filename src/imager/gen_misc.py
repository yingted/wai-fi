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

def call(overlay_dir):
	with lockfile.LockFile(app_dir), overlay.overlay_applied(overlay_dir, user_dir):
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
