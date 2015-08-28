import os.path
import fnmatch
import sys
import flasher
import config

def main():
	dev_dir = '/dev'
	dev_pat = 'ttyUSB*'
	args = sys.argv[1:]

	dev = None
	for dev in sorted(fnmatch.filter(os.listdir(dev_dir), dev_pat)):
		port = os.path.join(dev_dir, dev)
		flasher.flash_port(port, release=config.release)
	if dev is None:
		print >> sys.stderr, 'No devices matching', os.path.join(dev_dir, dev_pat)
		sys.exit(1)

if __name__ == '__main__':
	main()
