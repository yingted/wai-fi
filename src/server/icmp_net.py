from twisted.internet.protocol import Protocol
from twisted.python import log
import verify
import inspect
import decoder
import struct
import models
import imager.models
import config
import sql_hack

class IcmpNet(Protocol):
	MSG_LOG = 0
	MSG_LOG_FMT = '!BBH6s6s6sHb'
	MSG_LOG_FMT_SIZE = struct.calcsize(MSG_LOG_FMT)

	def __init__(self, *args, **kwargs):
		self._device_name = None
		self._decoder = decoder.Decoder(self, self._decode)
		self._session = config.sql_Session()

	def _decode(self, decoder):
		while True:
			msg_type, _ = decoder.read_struct('!bb')
			if msg_type == self.MSG_LOG:
				self._decode_log(decoder)
			else:
				log.err('invalid message type %d' % msg_type)
				self.transport.abortConnection()

	def _decode_log(self, decoder):
		msg_len, = decoder.read_struct('!h')
		count, rem = divmod(msg_len, self.MSG_LOG_FMT_SIZE)
		if rem != 0:
			log.err('invalid message length %d' % msg_len)

		headers = []
		for _ in xrange(count):
			fields = (self._device_name,) + decoder.read_struct(self.MSG_LOG_FMT)
			fields = models.Header.Tuple(*fields)
			for mac_field in 'addr1', 'addr2', 'addr3':
				old_value = getattr(fields, mac_field)
				new_value = ':'.join(['%02x'] * 6) % struct.unpack('!BBBBBB', old_value)
				fields = fields._replace(**{mac_field: new_value})
			headers.append(models.Header.from_tuple(fields))
		sql_hack.bulk_insert(self._session, headers)
		self._session.commit()

	def log(self, *args, **kwargs):
		log.msg('icmp_net://%s' % self._device_name, *args, **kwargs)

	def connectionMade(self):
		print 'Starting handshake with', self.transport.getPeer()
		verify.register_handshake_callback(self.transport, self.handshakeDone)

	def handshakeDone(self):
		conn = self.transport._tlsConnection
		device_name = verify.get_device_name(conn.get_peer_certificate())
		self._device_name = device_name
		self.log('connected')
		self._write_frame('Hello, World!\n')

	def _write_frame(self, frame):
		assert isinstance(frame, str)
		assert len(frame) <= 1280
		self.transport.write(frame)

	def dataReceived(self, data):
		self._decoder.write(data)

	def connectionLost(self, reason):
		self.log('disconnected:', reason.value)
