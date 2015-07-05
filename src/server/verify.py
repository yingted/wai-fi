from OpenSSL import SSL
import weakref

_handshake_callbacks = weakref.WeakKeyDictionary()

def register_handshake_callback(transport, cb):
	_handshake_callbacks[transport] = cb

def get_x509_cn(x509):
	for key, value in x509.get_subject().get_components():
		if key == 'CN':
			return value

def get_device_name(x509):
	name = get_x509_cn(x509)
	if name is not None:
		parts = name.split('.')
		if parts[-2:] == ['device', 'ssl']:
			return '.'.join(parts[:-2])

def info_cb(conn, where, ret):
	if where & SSL.SSL_CB_HANDSHAKE_DONE:
		# Improve on linear search?
		for key, value in _handshake_callbacks.items():
			if conn == key._tlsConnection:
				value()
				del _handshake_callbacks[key]

def verify_cb(connection, x509, errnum, errdepth, ok):
	if not ok:
		print 'invalid cert from subject:', x509.get_subject()
		return False
	if errdepth == 1:
		return get_x509_cn(x509) == 'ca.ssl'
	if errdepth == 0:
		return get_device_name(x509) is not None
	return False
