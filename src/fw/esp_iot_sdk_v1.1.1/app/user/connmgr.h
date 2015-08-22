#ifndef __CONNMGR_H__
#define __CONNMGR_H__

#include <user_config.h>

void connmgr_init(void);
void connmgr_start(void);
void connmgr_stop(void);
extern void connmgr_worker(SSL *ssl);
extern void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi);

#endif
