#ifndef __CONNMGR_H__
#define __CONNMGR_H__

#include <user_config.h>

void connmgr_init();
void connmgr_start();
void connmgr_stop();
typedef SSL connmgr_conn_t;
extern void connmgr_connect_cb();
extern err_t connmgr_send(struct pbuf *p);
extern void connmgr_sent_cb(u16_t len);
extern void connmgr_recv_cb(char *buf, u16_t len);
extern void connmgr_recved(u16_t len);
extern void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi);
extern void connmgr_disconnect_cb();
extern bool connmgr_connected;

#endif
