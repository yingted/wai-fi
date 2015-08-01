import fifobuffer
import gevent

class Decoder(object):
	r'''
	>>> def decode(decoder):
	...     print 'Decoding stream...'
	...     while True:
	...         decoder.delegate.write(decoder.read(ord(decoder.read(1))))
	>>> import sys
	>>> d = Decoder(sys.stdout, decode)
	>>> d.write('\0\5abc')
	Decoding stream...
	>>> d.write('d\n\3xy\n\4AB')
	abcd
	xy
	>>> d.write('C')
	>>> d.write('')
	>>> d.write('\n')
	ABC
	'''
	def __init__(self, delegate, dec):
		self.delegate = delegate
		self._buf = fifobuffer.FifoBuffer(self._switch_into_main)
		self._gen = gevent.Greenlet(dec, self)
		self._main = None
	def _switch_into_main(self):
		self._main.switch()
	def read(self, n):
		return self._buf.read(n)
	def write(self, data):
		assert self._main is None
		self._buf.write(data)
		self._main = gevent.getcurrent()
		self._gen.switch()
		assert self._main == gevent.getcurrent()
		self._main = None
