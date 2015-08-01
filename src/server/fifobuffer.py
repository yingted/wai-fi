import Queue

class FifoBuffer(object):
	'''
	>>> f = FifoBuffer()
	>>> f.write('01')
	>>> f.write('234')
	>>> f.read(3)
	'012'
	>>> f.read(0)
	''
	>>> f.read(2)
	'34'
	'''
	def __init__(self, empty_cb=None):
		'''
		Make an empty fifo buffer.
		'''
		self._first = ''
		self._index = 0
		self._rest = Queue.Queue()
		self._empty_cb = empty_cb
	def read(self, n):
		'''
		Block and read the next n bytes.
		'''
		ret = ''
		# While we need more
		while len(ret) + len(self._first) - self._index < n:
			assert 0 <= self._index <= len(self._first)
			ret += self._first[self._index:]
			self._index = None # try to throw an error
			while True:
				try:
					self._first = self._rest.get_nowait()
				except Queue.Empty:
					if not self._empty_cb:
						raise
					self._empty_cb()
				else:
					break
			self._index = 0

		# Pad it
		new_index = n - len(ret) + self._index
		ret += self._first[self._index:new_index]
		self._index = new_index
		assert len(ret) == n
		return ret
	def write(self, data):
		'''
		Write some data to the back of the fifo buffer.
		'''
		assert isinstance(data, str)
		self._rest.put(data)
