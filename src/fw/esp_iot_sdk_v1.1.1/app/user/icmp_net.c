#include "osapi.h"
#include "private_api.h"
#include "icmp_net.h"
#include "lwip/icmp.h"

void __wrap_icmp_input(struct pbuf *p, struct netif *inp) {
	os_printf("icmp_input()\n");
	__real_icmp_input(p, inp);
}

void icmp_net_tx() {
}
