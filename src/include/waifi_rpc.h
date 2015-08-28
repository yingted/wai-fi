#pragma once

#define WAIFI_MAX_FRAME_SIZE 1280

#define BYTE unsigned char
#ifdef SWIG
#define __attribute__(...)
#endif

// Include the SPI flash driver header
#ifdef __linux__
typedef uint32_t uint32;
typedef uint16_t uint16;
#include "../fw/3rdparty/esp_iot_rtos_sdk/include/espressif/spi_flash.h"
#endif

// RPC definitions (little-endian)
enum __attribute__((packed)) waifi_rpc_cmd {
	WAIFI_RPC_spi_flash_write,
	WAIFI_RPC_system_upgrade_userbin_check,
	WAIFI_RPC_upgrade_finish,
};

struct waifi_rpc_header {
	enum waifi_rpc_cmd cmd;
};

struct waifi_rpc_spi_flash_write {
	unsigned int addr;
	short len;
	BYTE data[0];
};

struct waifi_rpc_system_upgrade_userbin_check {
};

struct waifi_rpc_upgrade_finish {
};

struct waifi_rpc {
	struct waifi_rpc_header hdr;
	union {
		struct waifi_rpc_spi_flash_write spi_flash_write;
		struct waifi_rpc_system_upgrade_userbin_check system_upgrade_userbin_check;
		struct waifi_rpc_upgrade_finish upgrade_finish;
	};
};

enum __attribute__((packed)) waifi_msg_type {
	WAIFI_MSG_log,
	WAIFI_MSG_RPC_spi_flash_write,
	WAIFI_MSG_RPC_system_upgrade_userbin_check,
};

// IEEE 802.11 byte order, which is little endian

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

// Various messages, including RPC reply messages. Little-endian.

struct waifi_msg_log {
	short len;
	union {
		BYTE data[0];
		struct waifi_msg_log_logentry entries[0];
	};
};

struct waifi_msg_rpc_system_upgrade_userbin_check {
	unsigned char ret;
};

struct waifi_msg_rpc_spi_flash_write {
	SpiFlashOpResult ret;
};

struct waifi_msg_rpc_upgrade_finish {
};

struct waifi_msg_header {
    enum waifi_msg_type type;
    BYTE pad_;
};

struct __attribute__((packed)) waifi_msg {
	struct waifi_msg_header hdr;
    union {
        struct waifi_msg_log log;
		struct waifi_msg_rpc_system_upgrade_userbin_check rpc_system_upgrade_userbin_check;
		struct waifi_msg_rpc_spi_flash_write rpc_spi_flash_write;
		struct waifi_msg_rpc_upgrade_finish rpc_upgrade_finish;
    };
};
