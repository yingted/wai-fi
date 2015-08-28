from twisted.internet.protocol import Protocol
from twisted.python import log
import verify
import inspect
import decoder
import struct
import models
import imager.models
import config
import contextlib
import cStringIO as StringIO
import sql_hack
import waifi_rpc
import traceback
import collections
import abc
import gevent
import gevent.event
import imager.flasher

class multimap(object):
	'''
	Ordered multimap.
	TODO use gevent.queue.Queue when 1.1b3 is available, when it's ordered.
	'''
	def __init__(self, what={}):
		self._dict = collections.defaultdict(list)
		for k, v in dict(what).iteritems():
			self.insert(k, v)
	def insert(self, key, value):
		self._dict[key].append(value)
	def __contains__(self, key):
		return key in self._dict
	def pop(self, key):
		if key not in self:
			raise KeyError(key)
		x = self._dict[key]
		value = x.pop(0)
		if not x:
			del self._dict[key]
		return value

class IcmpNet(Protocol, object):
	'''
	Protocol for SSL connections through icmp_net.
	Perform authentication and decoding.
	'''
	__metaclass__ = abc.ABCMeta

	def __init__(self, *args, **kwargs):
		super(IcmpNet, self).__init__(*args, **kwargs)
		self._device_name = None
		self._decoder = decoder.Decoder(self, self._decode)

	@abc.abstractmethod
	def _decode(self, decoder):
		pass

	def log(self, *args, **kwargs):
		log.msg('icmp_net://%s' % self._device_name, *args, **kwargs)

	def connectionMade(self):
		self.log('Starting handshake with %s' % self.transport.getPeer())
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

class AsyncResponseMixin(object):
	'''
	Mixin for blocking until a result of a certain (concrete) type is available.
	All results are processed in order.
	'''
	def __init__(self, *args, **kwargs):
		super(AsyncResponseMixin, self).__init__(*args, **kwargs)
		self._response_results = multimap()

	def _got_response(self, response):
		res = self._response_results.pop(type(response))
		res.set(response)

	def _get_response(self, response_type):
		res = gevent.event.AsyncResult()
		self._response_results.insert(response_type, res)
		return res.get()

class WaifiIcmpNet(IcmpNet, AsyncResponseMixin):
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
				msg = waifi_rpc.read_waifi_msg_header(decoder)
				if msg.type == waifi_rpc.WAIFI_MSG_log:
					self._decode_log(decoder)
				elif msg.type == waifi_rpc.WAIFI_MSG_RPC_spi_flash_write:
					self._got_response(waifi_rpc.read_waifi_msg_rpc_spi_flash_write(decoder))
				elif msg.type == waifi_rpc.WAIFI_MSG_RPC_system_upgrade_userbin_check:
					self._got_response(waifi_rpc.read_waifi_msg_rpc_system_upgrade_userbin_check(decoder))
				else:
					raise TypeError('invalid message type %d' % msg.type)
		except:
			traceback.print_exc()
			log.err('could not parse message')
			self.transport.abortConnection()

	def _decode_log(self, decoder):
		log_hdr = waifi_rpc.read_waifi_msg_log(decoder)
		count, rem = divmod(log_hdr.len, waifi_rpc.sizeof_waifi_msg_log_logentry)
		if rem != 0:
			log.err('invalid message length %d' % log_hdr.len)

		headers = []
		for _ in xrange(count):
			# entry must have a reference
			entry = waifi_rpc.read_waifi_msg_log_logentry(decoder)
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
		gevent.Greenlet.spawn(self.do_fota_upgrade)

	def do_fota_upgrade(self):
		userbin = self._rpc_system_upgrade_userbin_check()
		# Build the other userbin
		if userbin == waifi_rpc.UPGRADE_FW_BIN1:
			build_userbin = 2
		elif userbin == waifi_rpc.UPGRADE_FW_BIN2:
			build_userbin = 1
		else:
			raise ValueError('invalid userbin %r' % userbin)
		print 'build_userbin:', build_userbin
		with imager.flasher.get_images(
				mac=self._device_name,
				release=False,
				extra_env={
					'BUILD_USERBIN': str(build_userbin),
				},
			) as images:
			for addr, path in images.iteritems():
				assert addr.startswith('0x')
				addr = int(addr, 16)
				assert addr >= 0
				if addr > 0:
					print addr, path

	@contextlib.contextmanager
	def _rpc(self, cmd):
		'''
		Helper to manage writing a frame to the remote.
		Everything written in the context will be in the same frame as the header.
		'''
		remote = StringIO.StringIO()
		hdr = waifi_rpc.waifi_rpc_header()
		hdr.cmd = cmd
		waifi_rpc.write(remote, hdr)
		yield remote
		self._write_frame(remote.getvalue())

	def _rpc_system_upgrade_userbin_check(self):
		with self._rpc(waifi_rpc.WAIFI_RPC_system_upgrade_userbin_check) as remote:
			pass
		return self._get_response(waifi_rpc.waifi_msg_rpc_system_upgrade_userbin_check).ret

	def _rpc_spi_flash_write(self, addr, data):
		with self._rpc(waifi_rpc.WAIFI_RPC_spi_flash_write) as remote:
			arg = waifi_rpc_spi_flash_write()
			arg.addr = addr
			arg.len = len(data)
			waifi_rpc.write(remote, arg)
			remote.write(data)
		return self._get_response(waifi_msg_rpc_spi_flash_write).ret

	def _rpc_upgrade_finish(self):
		with self._rpc(waifi_rpc.WAIFI_RPC_upgrade_finish) as remote:
			pass
