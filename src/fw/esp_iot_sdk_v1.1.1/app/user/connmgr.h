#ifndef __CONNMGR_H__
#define __CONNMGR_H__

#include <user_config.h>

void connmgr_init(void);
void connmgr_start(void);
void connmgr_stop(void);
/**
 * Enqueue a pbuf for writing.
 * Must be called from connmgr_record_cb or connmgr_idle_cb.
 */
void connmgr_write(struct pbuf *p);
extern void connmgr_record_cb(SSL *ssl, uint8_t *buf, int len);
extern void connmgr_idle_cb(SSL *ssl);
extern void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi);

#endif
