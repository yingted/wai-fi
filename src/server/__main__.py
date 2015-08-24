import geventreactor
geventreactor.install()

from OpenSSL import SSL
from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory
from icmp_net import IcmpNet
from twisted.python import log
import sys
import verify
import config
import os.path
import inspect

ca_key_path = os.path.join(config.data_dir, 'master/default_ca_private_key.pem')
ca_cert_path = os.path.join(config.data_dir, 'master/default_ca_certificate.pem')

def main():
	log.startLogging(sys.stdout)

	factory = Factory()
	factory.protocol = IcmpNet

	ctx_factory = ssl.DefaultOpenSSLContextFactory(
		ca_key_path,
		ca_cert_path,
		sslmethod=SSL.TLSv1_1_METHOD
	)

	ctx = ctx_factory.getContext()

	ctx.set_info_callback(verify.info_cb)

	ctx.set_verify(
		SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
		verify.verify_cb
	)

	# Since we have self-signed certs we have to explicitly
	# tell the server to trust them.
	ctx.load_verify_locations(ca_cert_path)

	reactor.listenSSL(55555, factory, ctx_factory, backlog=1024)
	reactor.run()

if __name__ == '__main__':
	main()
