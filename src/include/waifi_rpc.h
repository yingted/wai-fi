#pragma once

#define WAIFI_MAX_FRAME_SIZE 1280

#define BYTE unsigned char
#ifdef SWIG
#define __attribute__(...)
#endif

enum __attribute__((packed)) waifi_rpc_cmd {
	WAIFI_RPC_spi_flash_write,
	WAIFI_RPC_system_upgrade_userbin_check,
};

struct waifi_rpc_header {
	enum waifi_rpc_cmd cmd;
};

struct waifi_rpc {
	struct waifi_rpc_header hdr;
	BYTE data[0];
};

enum __attribute__((packed)) waifi_msg_type {
	WAIFI_MSG_log,
};

struct waifi_msg_log_logentry {
    BYTE header_prefix[24];
    char rssi;
};

struct waifi_msg_log {
	short len;
	union {
		BYTE data[0];
		struct waifi_msg_log_logentry entry[0];
	};
};

struct waifi_msg_header {
    enum waifi_msg_type type;
    BYTE pad_;
};

struct waifi_msg {
	struct waifi_msg_header hdr;
    union {
        struct waifi_msg_log log;
    };
};

union waifi_msg_buf {
	struct waifi_msg value;
	BYTE buf[sizeof(struct waifi_msg)];
};

union waifi_rpc_buf {
	struct waifi_rpc value;
	BYTE buf[sizeof(struct waifi_rpc)];
};
