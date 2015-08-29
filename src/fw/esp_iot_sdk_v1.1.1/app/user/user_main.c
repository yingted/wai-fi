#include <user_config.h>
#include <user_interface.h>
#include <debug_esp.h>
#include <connmgr.h>
#include <gdb_stub.h>
#include <lwip/netif.h>
#include <waifi_rpc.h>
#include <stdlib.h>

#define UPGRADE_FLAG_IDLE 0x00
#define UPGRADE_FLAG_START 0x01
#define UPGRADE_FLAG_FINISH 0x02

#define LOGBUF_SIZE 1024
#define MAX_LOGBUF 2

__attribute__((weak))
ICACHE_FLASH_ATTR
void user_rf_pre_init(void) {}

#ifndef UART_LOGGING
ICACHE_FLASH_ATTR
static void noop_put1c() {}
#endif

__attribute__((optimize("omit-frame-pointer")))
size_t my_spi_flash_erase_sector_impl(size_t sec) {
    //return ((size_t(*)(size_t))0x40004a00)(sec);
    size_t *local0 = *(size_t **)0x3fffc714;
    // args are: 0x80000, 0x1000
    // looks like division:
    // ((long(*)(long, long))0x4000e21c)(1234567, 2345) = 526
    return ((size_t(*)(size_t, size_t))0x4000e21c)(local0[4 / 4], local0[12 / 4]);
}

__attribute__((optimize("omit-frame-pointer")))
size_t my_spi_flash_erase_sector(size_t sec) {
    __asm__ __volatile__("memw");
    ((size_t *)0x60000600)[0x314 / 4] = 115;
    ((void(*)(size_t))0x400047f0)(0x60000600);
    size_t ret = my_spi_flash_erase_sector_impl(sec);
    extern void Cache_Read_Enable_New();
    Cache_Read_Enable_New();
    return ret;
}

ICACHE_FLASH_ATTR
void user_init(void) {
    system_update_cpu_freq(160);
    extern void uart_div_modify(size_t uart_no, size_t divider);
    uart_div_modify(0, UART_CLK_FREQ / 115200);
#ifndef UART_LOGGING
    os_install_putc1(noop_put1c);
#endif
    debug_esp_install_exc_handler();
    gdb_stub_init();
#ifdef GDB_STUB_STARTUP
    gdb_stub_break();
#endif
    user_dprintf("Starting up...");
#ifndef NDEBUG
    ets_wdt_disable();
#endif

    gdb_stub_break();
    user_dprintf("ret: %d", my_spi_flash_erase_sector(128));
    //connmgr_init();
    //connmgr_start();
}

static struct pbuf *logbuf_head = NULL, *logbuf_tail = NULL;

/**
 * Try to send logbuf_head.
 * Should called after the worker's IDLE (or any other blocking call).
 */
ICACHE_FLASH_ATTR
void connmgr_idle_cb(SSL *ssl) {
    USER_INTR_LOCK();
    if (logbuf_head != logbuf_tail) {
        struct pbuf *const to_send = logbuf_head;
        assert(to_send);
        pbuf_ref(logbuf_head = to_send->next);
        assert(logbuf_head);
        assert(pbuf_clen(to_send) > 1);
        pbuf_dechain(to_send);
        assert(logbuf_head->ref >= 1);
        size_t logged_size = LOGBUF_SIZE - to_send->len;
        struct waifi_msg *header = (struct waifi_msg *)((char *)to_send->payload - logged_size);
        switch (header->hdr.type) {
            case WAIFI_MSG_log:;
                _Static_assert((sizeof(header->hdr) + sizeof(header->log)) == 4, "Wrong header size");
                _Static_assert(offsetof(struct waifi_msg, log.len) == 2, "Wrong offset for len");
                header->log.len = (short)(logged_size - (sizeof(header->hdr) + sizeof(header->log)));
                break;
            default:
                assert(false);
        }
        if (pbuf_header(to_send, logged_size)) {
            assert(false);
        }
        pbuf_realloc(to_send, logged_size);
        connmgr_write(to_send);
    }
    USER_INTR_UNLOCK();
}

ICACHE_FLASH_ATTR
void connmgr_record_cb(SSL *ssl, uint8_t *buf, int len) {
#if 0
    {
        int i;
        os_printf("connmgr_record_cb: buf: ");
        for (i = 0; i != len; ++i) {
            os_printf("%02x", buf[i]);
        }
        os_printf("\n");
    }
#endif
    struct waifi_rpc *rpc = (struct waifi_rpc *)buf;
    if (len < sizeof(struct waifi_rpc_header)) {
        return;
    }

    user_dprintf("Got command %d", rpc->hdr.cmd);

    struct pbuf *p = NULL;
    struct waifi_msg *msg = NULL;
#define REPLY_ALLOC(size_val) \
    do { \
        const size_t size = sizeof(msg->hdr) + (size_val); \
        p = pbuf_alloc(PBUF_RAW, size, PBUF_RAM); \
        msg = p->payload; \
        os_memset(&msg->hdr, 0, sizeof(msg->hdr)); \
    } while (0)
    switch (rpc->hdr.cmd) {
        case WAIFI_RPC_system_upgrade_userbin_check:
            REPLY_ALLOC(sizeof(struct waifi_msg_rpc_system_upgrade_userbin_check));
            msg->hdr.type = WAIFI_MSG_RPC_system_upgrade_userbin_check;
            msg->rpc_system_upgrade_userbin_check.ret = system_upgrade_userbin_check();
            system_upgrade_flag_set(UPGRADE_FLAG_IDLE);
            break;
        case WAIFI_RPC_spi_flash_write:;
            _Static_assert(offsetof(struct waifi_rpc, spi_flash_write.len) == 2, "wrong len offset");
            _Static_assert(offsetof(struct waifi_rpc, spi_flash_write.addr) == 4, "wrong addr offset");
            REPLY_ALLOC(sizeof(struct waifi_msg_rpc_spi_flash_write));
            msg->hdr.type = WAIFI_MSG_RPC_spi_flash_write;
            {
                SpiFlashOpResult ret = SPI_FLASH_RESULT_OK;
                struct waifi_rpc_spi_flash_write *arg = &rpc->spi_flash_write;
#define ASSIGN(dst, src) \
    _Static_assert(sizeof(dst) == sizeof(src), "assignment size mismatch"); \
    os_memcpy(&(dst), &(src), sizeof(dst));
                uint32_t addr;
                ASSIGN(addr, arg->addr);
                int16_t len;
                ASSIGN(len, arg->len);
                uint16_t sec = addr >> 12;
                if (addr == (sec << 12)) { // Erase if we start on a sector
                    ret = spi_flash_erase_sector(sec);
                    user_dprintf("spi_flash_erase_sector(%d) = %d", sec, ret);
                }
                assert(ssl->bm_all_data <= arg->data);
                assert(arg->data + len <= ssl->bm_all_data + RT_MAX_PLAIN_LENGTH + RT_EXTRA + sizeof(uint32) - 1);
                _Static_assert(__builtin_popcount(sizeof(uint32)) == 1, "size not a power of 2");
                uint32 *buf = (uint32 *)((((size_t)arg->data + sizeof(uint32) - 1)) & ~(sizeof(uint32) - 1));
                assert(((size_t)buf) >= ((size_t)arg->data));
                if (ret == SPI_FLASH_RESULT_OK) {
                    // Shift the data to an aligned address
                    os_memmove(buf, arg->data, len);
                    ret = spi_flash_write(addr, buf, len);
                    user_dprintf("spi_flash_write(%p, %p, %d) = %d", addr, buf, len, ret);
                }
                msg->rpc_spi_flash_write.ret = ret;
            }
            break;
        case WAIFI_RPC_upgrade_finish:
            system_upgrade_flag_set(UPGRADE_FLAG_FINISH);
            system_upgrade_reboot();
            return;
        default:
            user_dprintf("unknown command %d", rpc->hdr.cmd);
            return;
    }
    connmgr_write(p);
}

ICACHE_FLASH_ATTR
void connmgr_packet_cb(uint8_t *payload, short header_len, short body_len, int rssi) {
    typedef struct waifi_msg_log_logentry logentry_t;
    _Static_assert(sizeof(logentry_t) == 25, "wrong struct size");
    if (header_len < sizeof(((logentry_t *)NULL)->header_prefix)) {
        return;
    }

    USER_INTR_LOCK();
    while (!logbuf_tail || pbuf_header(logbuf_tail, -(s16_t)sizeof(logentry_t))) {
        {
            u8_t num_bufs = 0;

            if (logbuf_head) {
                num_bufs = pbuf_clen(logbuf_head);
            }
            if (num_bufs >= MAX_LOGBUF) {
                goto out;
            }
        }

        user_dprintf("allocating new buf");
        struct pbuf *new_tail = pbuf_alloc(PBUF_RAW, LOGBUF_SIZE, PBUF_RAM);
        assert(new_tail->len == LOGBUF_SIZE);
        if (!new_tail) {
            user_dprintf("dropping log entry");
            goto out;
        }

        {
            _Static_assert(sizeof(enum waifi_msg_type) == 1, "msg type wrong size");
            _Static_assert(sizeof(struct waifi_msg_header) == 2, "msg header wrong size");
            _Static_assert(sizeof(struct waifi_msg_log) == 2, "msg log wrong size");
            struct waifi_msg_header *const header = (struct waifi_msg_header *)new_tail->payload;
            pbuf_header(new_tail, -(u16_t)(sizeof(*header) + sizeof(struct waifi_msg_log)));
            os_memset(header, 0, sizeof(*header));
            header->type = WAIFI_MSG_log; // We'll write the rest later
        }

        logbuf_tail = new_tail;
        if (logbuf_head) {
            pbuf_cat(logbuf_head, logbuf_tail);
        } else {
            logbuf_head = logbuf_tail;
        }
    }

    logentry_t *const dst = (logentry_t *)logbuf_tail->payload - 1;
    os_memcpy(dst->header_prefix, payload, sizeof(dst->header_prefix));
    dst->rssi = rssi;

out:
    USER_INTR_UNLOCK();
}
