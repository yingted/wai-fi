#pragma once

#define WAIFI_MAX_FRAME_SIZE 1280

enum waifi_rpc_cmd {
	WAIFI_RPC_spi_flash_write,
	WAIFI_RPC_system_upgrade_userbin_check,
};
typedef enum waifi_rpc_cmd waifi_rpc_cmd_t;
