#ifndef __CONNMGR_H__
#define __CONNMGR_H__

#include <user_config.h>

void connmgr_init();
void connmgr_start();
void connmgr_stop();
struct espconn conn;
extern void connmgr_connect_cb(struct espconn *conn);
extern void connmgr_sent_cb(struct espconn *conn);
extern void connmgr_recv_cb(struct espconn *conn, char *buf, unsigned short len);
extern void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi);
extern void connmgr_disconnect_cb();
extern bool connmgr_connected;

#endif
