#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <asm/ioctl.h>

#include "tuntap.h"

int tun_alloc(char *dev, short type) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return fd;

	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN dev ice (no Ethernet headers)
	 *        IFF_TAP   - TAP dev ice
	 *
	 *        IFF_NO_PI - Do not  provide packet information
	 */
	ifr.ifr_flags = type;
	if( *dev )
		strncpy(ifr.ifr_name, dev,  IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}
