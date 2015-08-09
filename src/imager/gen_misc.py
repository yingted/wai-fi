import subprocess
import fslock
import os.path
import re
import contextlib
import overlay
import shutil
import tempfile
import config

sdk_dir = config.sdk_dir
bin_dir = os.path.join(sdk_dir, 'bin')
app_dir = os.path.join(sdk_dir, 'app')
build_dir = os.path.join(app_dir, 'user')

def call(overlay_dir, release=False):
	with fslock.FsLock(app_dir), overlay.overlay_applied(overlay_dir=overlay_dir, build_dir=build_dir):
		env = None
		if release:
			env = dict(os.environ)
			env.update({
				'FLAVOR': 'release',
				'GDB_STUB_STARTUP': '0',
				'DEBUG_ESP': '0',
				'GDB_STUB': '0',
				'UART_LOGGING': '0',
			})
			subprocess.check_call('make clean', cwd=app_dir)
		p = subprocess.Popen(('bash', 'gen_misc.sh'), cwd=app_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
		stdout, stderr = p.communicate()
		p.wait()

		paths = {}
		m = re.match(pattern=r'.*^Generate .* successully in.* (\S+)\.\n(.*)', string=stdout, flags=re.M | re.S)
		if not m:
			raise Exception('Compilation failed')
		out_dir, rest = m.groups()
		for m in re.finditer(r'^([^-\n ]+)-+>(0x[0-9a-f]+)$', rest, flags=re.M):
			name, addr = m.groups()
			out_path = os.path.join(bin_dir, name)
			paths[addr] = out_path
		return paths
