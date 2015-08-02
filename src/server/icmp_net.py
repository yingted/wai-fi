from twisted.internet.protocol import Protocol
from twisted.python import log
import verify
import inspect
import decoder
import struct
import models

class IcmpNet(Protocol):
	MSG_LOG = 0
	MSG_LOG_FMT = '!BBH6s6s6sHb'
	MSG_LOG_FMT_SIZE = struct.calcsize(MSG_LOG_FMT)

	def __init__(self, *args, **kwargs):
		self._device_name = None
		self._decoder = decoder.Decoder(self, self._decode)
		self._session = models.Session()

	def _decode(self, decoder):
		while True:
			msg_type, _ = decoder.read_struct('!bb')
			if msg_type == self.MSG_LOG:
				msg_len, = decoder.read_struct('!h')
				count, rem = divmod(msg_len, self.MSG_LOG_FMT_SIZE)
				if rem != 0:
					log.err('invalid message length %d' % msg_len)
				headers = []
				for _ in xrange(count):
					headers.append(models.Header.from_tuple(decoder.read_struct(self.MSG_LOG_FMT)))
				self._session.bulk_save_objects(headers)
				self._session.commit()
			else:
				log.err('invalid message type %d' % msg_type)
				self.abortConnection()

	def log(self, *args, **kwargs):
		log.msg('icmp_net://%s' % self._device_name, *args, **kwargs)

	def connectionMade(self):
		verify.register_handshake_callback(self.transport, self.handshakeDone)

	def handshakeDone(self):
		conn = self.transport._tlsConnection
		device_name = verify.get_device_name(conn.get_peer_certificate())
		self._device_name = device_name
		self.log('connected')

	def dataReceived(self, data):
		self._decoder.write(data)

	def connectionLost(self, reason):
		self.log('disconnected:', reason.value)
