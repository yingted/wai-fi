#ifndef __CONNMGR_H__
#define __CONNMGR_H__

#include "user_config.h"

void connmgr_init();
extern void connmgr_connect_cb(struct espconn *conn);
extern void connmgr_sent_cb(struct espconn *conn);
extern void connmgr_recv_cb(struct espconn *conn, char *buf, unsigned short len);
extern void connmgr_disconnect_cb();
extern bool connmgr_connected;

#endif
