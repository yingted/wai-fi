import filelock
import contextlib
import os.path
import fcntl

@contextlib.contextmanager
def DirLock(path):
	fd = os.open(path, os.O_RDONLY | os.O_NOCTTY, 0700)
	fcntl.flock(fd, fcntl.LOCK_EX)
	try:
		yield
	finally:
		# fcntl.flock(fd, fcntl.LOCK_UN)
		os.close(fd)

def FsLock(path):
	if os.path.isdir(path):
		return DirLock(path)
	return filelock.FileLock(path)
