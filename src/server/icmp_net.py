from twisted.internet.protocol import Protocol
from twisted.python import log
import verify
import inspect

class IcmpNet(Protocol):
	def __init__(self, *args, **kwargs):
		self._device_name = None

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
		self.log('received:', repr(data))

	def connectionLost(self, reason):
		self.log('disconnected:', reason.value)
