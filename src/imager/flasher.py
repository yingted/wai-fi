import lockfile
import sys
import subprocess
import gen_misc
import overlay

def import_esptool():
	global esptool, esptool_path
	import imp
	import distutils.spawn
	esptool_path = distutils.spawn.find_executable('esptool.py')
	esptool = imp.load_source('esptool', esptool_path)

def flash_port(port, baud=115200):
	import_esptool()

	with lockfile.LockFile(port):
		esptool.esp = esptool.ESPROM(port=port, baud=baud)
		mac = esptool.esp.read_mac()
		mac = map('%02x'.__mod__, mac)
		mac_str = ''.join(mac)
		with overlay.get_overlay_dir(mac_str) as overlay_dir:
			images = gen_misc.call(overlay_dir=overlay_dir)
			cmd = [esptool_path, '-p', port, '-b', str(baud), 'write_flash']
			for addr, image in images.itervalues():
				cmd.extend([hex(addr), image])
			print >> sys.stderr, 'Flashing device', ':'.join(mac), 'with:', cmd
			with overlay_dir.lock_for_flashing(port):
				subprocess.check_call(cmd)
