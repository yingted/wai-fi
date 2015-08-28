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

struct waifi_msg_log_logentry_header_fields {
	BYTE fc_type;
	BYTE fc_flags;
	unsigned short dur;
	BYTE addr1[6];
	BYTE addr2[6];
	BYTE addr3[6];
	unsigned short seqid;
};

struct __attribute__((packed)) waifi_msg_log_logentry {
	union {
		BYTE header_prefix[24];
		struct waifi_msg_log_logentry_header_fields header_fields;
	};
    BYTE rssi;
};

struct waifi_msg_log {
	short len;
	union {
		BYTE data[0];
		struct waifi_msg_log_logentry entries[0];
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
