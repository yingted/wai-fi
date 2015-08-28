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
import waifi_rpc
import traceback
import abc

class IcmpNet(Protocol, object):
	'''
	Protocol for SSL connections through icmp_net.
	Perform authentication and decoding.
	'''
	__metaclass__ = abc.ABCMeta

	def __init__(self, *args, **kwargs):
		self._device_name = None
		self._decoder = decoder.Decoder(self, self._decode)

	@abc.abstractmethod
	def _decode(self, decoder):
		pass

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

	def _write_frame(self, frame):
		assert isinstance(frame, str)
		assert len(frame) <= 1280
		self.transport.write(frame)

	def dataReceived(self, data):
		self._decoder.write(data)

	def connectionLost(self, reason):
		self.log('disconnected:', reason.value)

class WaifiIcmpNet(IcmpNet):
	r'''
	Protocol to read/write the various messages sent by the remote.
	>>> waifi_rpc.sizeof_waifi_msg_header
	2L
	>>> waifi_rpc.sizeof_waifi_msg_log
	2L
	>>> waifi_rpc.sizeof_waifi_msg_log_logentry
	25L
	>>> import struct
	>>> frame = struct.pack('BBh24sb', waifi_rpc.WAIFI_MSG_log, 0, 25, 'x' * 24, 100)
	>>> frame
	'\x00\x00\x19\x00xxxxxxxxxxxxxxxxxxxxxxxxd'
	>>> w = WaifiIcmpNet()
	>>> headers = []
	>>> w._save_headers = headers.extend
	>>> w.dataReceived(frame * 3)
	>>> headers # doctest: +ELLIPSIS
	[<models.Header object at ...>, ...]
	>>> [x.rssi for x in headers]
	[100L, 100L, 100L]
	>>> sorted(x.__dict__.iteritems()) # doctest: +ELLIPSIS
	[...('addr1', '78:78:78:78:78:78'), ('addr2', '78:78:78:78:78:78'), ('addr3', '78:78:78:78:78:78'), ('dur', 30840L), ('fc_flags', 120L), ('fc_type', 120L), ('logging_device', None), ('rssi', 100L), ('seqid', 30840L)]
	'''

	def __init__(self, *args, **kwargs):
		super(WaifiIcmpNet, self).__init__(*args, **kwargs)
		self._session = config.sql_Session()

	def _decode(self, decoder):
		try:
			while True:
				msg = waifi_rpc.scan_waifi_msg_header(decoder)
				if msg.type == waifi_rpc.WAIFI_MSG_log:
					self._decode_log(decoder)
				else:
					raise TypeError('invalid message type %d' % msg.type)
		except:
			traceback.print_exc()
			log.err('could not parse message')
			self.transport.abortConnection()

	def _decode_log(self, decoder):
		log_hdr = waifi_rpc.scan_waifi_msg_log(decoder)
		count, rem = divmod(log_hdr.len, waifi_rpc.sizeof_waifi_msg_log_logentry)
		if rem != 0:
			log.err('invalid message length %d' % log_hdr.len)

		headers = []
		for _ in xrange(count):
			# entry must have a reference
			entry = waifi_rpc.scan_waifi_msg_log_logentry(decoder)
			fields = entry.header_fields
			header = models.Header(logging_device=self._device_name, rssi=entry.rssi, **{
				field_name: getattr(fields, field_name) for field_name in fields.__swig_setmethods__.iterkeys()
			})
			for mac_field in 'addr1', 'addr2', 'addr3':
				value = getattr(header, mac_field)
				# Convert the byte array to a string
				value = waifi_rpc.strndup(value, 6)
				# Then, convert it to hex
				value = ':'.join(['%02x'] * 6) % struct.unpack('!BBBBBB', value)
				setattr(header, mac_field, value)
			headers.append(header)
		self._save_headers(headers)
	
	def _save_headers(self, headers):
		sql_hack.bulk_insert(self._session, headers)
		self._session.commit()

	def handshakeDone(self):
		super(WaifiIcmpNet, self).handshakeDone()
		self._write_frame('Hello, World!\n')
