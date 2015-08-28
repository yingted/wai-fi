import fslock
import sys
import subprocess
import gen_misc
import overlay
import contextlib

def import_esptool():
	global esptool, esptool_path
	import imp
	import distutils.spawn
	esptool_path = distutils.spawn.find_executable('esptool.py')
	esptool = imp.load_source('esptool', esptool_path)

@contextlib.contextmanager
def get_images(mac, release=False, extra_env={}):
	with overlay.get_overlay_dir(mac=mac) as overlay_dir:
		yield gen_misc.call(overlay_dir=overlay_dir, release=release, extra_env=extra_env)

def flash_port(port, baud=921600, release=False, extra_env={}):
	import_esptool()

	print >> sys.stderr, 'Probing', port
	with fslock.FsLock(port):
		esptool.esp = esptool.ESPROM(port=port, baud=baud)
		esptool.esp.connect()
		mac = esptool.esp.read_mac()
		mac = map('%02x'.__mod__, mac)
		mac_text = ':'.join(mac)
		print >> sys.stderr, 'Found device', mac_text, 'at', port
		mac = ''.join(mac)
		with get_images(mac=mac, release=release, extra_env=extra_env) as images:
			cmd = [esptool_path, '-p', port, '-b', str(baud), 'write_flash']
			for addr, image in images.iteritems():
				cmd.extend((addr, image))
			print >> sys.stderr, 'Flashing device', mac_text, 'with:', cmd
			subprocess.check_call(cmd)
