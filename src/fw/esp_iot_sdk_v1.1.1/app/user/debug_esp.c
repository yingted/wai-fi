#include <user_config.h>
#include <osapi.h>
#include <private_api.h>
#include <c_types.h>
#include <debug_esp.h>
#include <lwip/icmp.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/netif/etharp.h>
#include <stddef.h>
#include <xtensa/config/core-isa.h>

__attribute__((always_inline))
static inline void print_stack_() {
    void *sp;
    asm volatile("mov %0, a1" : "=r" (sp));
    {
        os_printf("forward from sp=%p:", sp);
        int i;
        for (i = 0; i < 64; ++i) {
            os_printf(" %p", ((void **)sp)[i]);
        }
        os_printf("\n");
    }
    {
        os_printf("back from sp=%p:", sp);
        int i;
        for (i = 0; i < 64; ++i) {
            os_printf(" %p", ((void **)sp)[~i]);
        }
        os_printf("\n");
    }
}

#ifndef NDEBUG
ICACHE_FLASH_ATTR
void print_stack() {
    print_stack_();
}
#endif

#ifdef DEBUG_ESP

#define esf_buf_printf os_printf
//#define esf_buf_printf(...)

ICACHE_FLASH_ATTR
void assert_heap_(char *file, int line) {
    //user_dprintf("%s:%d", file, line);
    esf_buf_printf("%s:%d ", file, line);
    uint32_t heap = system_get_free_heap_size();
    if (!(8000 <= heap && heap <= 50000)) {
        user_dprintf("heap: %d", heap);
        assert(false);
    }
    //show_esf_buf();
    esf_buf_printf("ok\n");
}

static bool is_mem_error = false;
ICACHE_FLASH_ATTR
void mem_error() {
    is_mem_error = true;
    show_esf_buf();
    assert(false);
}

struct exc_arg {
    size_t xt_pc;
    size_t xt_ps;
    size_t xt_sar;
    size_t xt_vpri;
    size_t xt_a2;
    size_t xt_a3;
    size_t xt_a4;
    size_t xt_a5;
    size_t xt_exccause;
    size_t xt_lcount;
    size_t xt_lbeg;
    size_t xt_lend;
};

ICACHE_FLASH_ATTR
static void exc_handler(struct exc_arg *exc) {
    size_t exc_cause;
    void *exc_vaddr;
    asm volatile("rsr.exccause %0" : "=r" (exc_cause));
    asm volatile("rsr.excvaddr %0" : "=r" (exc_vaddr));

    if (exc) {
        struct exc_arg data = *exc;
        user_dprintf("Exception %d at %p", exc_cause, exc_vaddr);
        user_dprintf(
            "pc=%p ps=%p sar=%p vpri=%p a2=%p a3=%p a4=%p a5=%p exccause=%p lcount=%p lbeg=%p lend=%p",
            data.xt_pc, data.xt_ps, data.xt_sar, data.xt_vpri, data.xt_a2, data.xt_a3, data.xt_a4, data.xt_a5, data.xt_exccause, data.xt_lcount, data.xt_lbeg, data.xt_lend
        );
    }
    print_stack_();
    assert(false);
}

ICACHE_FLASH_ATTR
void debug_esp_install_exc_handler() {
    //_xtos_set_exception_handler(3, exc_handler);
    _xtos_set_exception_handler(9, exc_handler);
    _xtos_set_exception_handler(28, exc_handler);
    _xtos_set_exception_handler(29, exc_handler);
}

void __real_etharp_tmr();
ICACHE_FLASH_ATTR
void __wrap_etharp_tmr() {
    assert_heap();
    __real_etharp_tmr();
    assert_heap();
}

u16_t
__real_inet_chksum_pseudo(struct pbuf *p, 
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pseudo(struct pbuf *p, 
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len) {
    register void *a0_ asm("a0");
    void *a0 = a0_;
    user_dprintf("%p, from %p", p, a0);
    user_dprintf("ref: %d, len: %d, tot_len: %d", p->ref, p->len, p->tot_len);
    if (p->ref != 1) {
        exc_handler(NULL);
    }
    assert(p->ref == 1);
    // from: 0x401052ba
    // func: 0x401051b4
    // from: 0x40262a78 (tcp_output)
    u16_t ret = __real_inet_chksum_pseudo(p, src, dest, proto, proto_len);
    user_dprintf("%u", (unsigned)ret);
    return ret;
}

u16_t
__real_inet_chksum_pseudo_partial(struct pbuf *p,
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len, u16_t chksum_len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pseudo_partial(struct pbuf *p,
       ip_addr_t *src, ip_addr_t *dest,
       u8_t proto, u16_t proto_len, u16_t chksum_len) {
    //user_dprintf("%p", p);
    return __real_inet_chksum_pseudo_partial(p, src, dest, proto, proto_len, chksum_len);
}

u16_t
__real_inet_chksum(void *dataptr, u16_t len);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum(void *dataptr, u16_t len) {
    //user_dprintf("%p", dataptr);
    return __real_inet_chksum(dataptr, len);
}

u16_t
__real_inet_chksum_pbuf(struct pbuf *p);
ICACHE_FLASH_ATTR
u16_t
__wrap_inet_chksum_pbuf(struct pbuf *p) {
    //user_dprintf("%p", p);
    return __real_inet_chksum_pbuf(p);
}

void *__real_pvPortMalloc(size_t size);
void *pvPortZalloc(size_t size);
ICACHE_FLASH_ATTR
void *__wrap_pvPortMalloc(size_t size) {
    register void *a0_ asm("a0");
    void *a0 = a0_;
    //size += 32;
    //void *ret = __real_pvPortMalloc(size);
    void *ret = pvPortZalloc(size);
    if (!ret) {
        user_dprintf("pvPortMalloc(%u) failed, called from %p", size, a0);
        mem_error();
    }
    return (char *)ret;
}

void *__real_esf_buf_alloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_esf_buf_alloc(long a, long b) {
    //USER_INTR_LOCK();
    void *ret = __real_esf_buf_alloc(a, b);
    //USER_INTR_UNLOCK();
    if (!ret) {
        user_dprintf("%p %ld => %p", (void *)a, b, ret);
        assert_heap();
        assert(false);
    }
    return ret;
}

void *__real_esf_rx_buf_alloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_esf_rx_buf_alloc(long a, long b) {
    //assert_heap();
    //USER_INTR_LOCK();
    void *ret = __real_esf_rx_buf_alloc(a, b);
    //USER_INTR_UNLOCK();
    if (!ret) {
        user_dprintf("%ld %ld => %p", a, b, ret);
        assert_heap();
        assert(false);
    }
    return ret;
}

void *__real_mem_malloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_mem_malloc(long a, long b) {
    void *ret = __real_mem_malloc(a, b);
    if (!ret) {
        user_dprintf("%ld %ld", a, b);
        assert(false);
    }
    return ret;
}

void *__real_mem_realloc(long a, long b);
ICACHE_FLASH_ATTR
void *__wrap_mem_realloc(long a, long b) {
    void *ret = __real_mem_realloc(a, b);
    if (!ret) {
        user_dprintf("%ld %ld", a, b);
        assert(false);
    }
    return ret;
}

ICACHE_FLASH_ATTR
void show_esf_buf() {
    int lmacIsActive();
    esf_buf_printf("lmac: %d ", lmacIsActive());
    struct node {
        char data_[32];
        struct node *next;
    } **base = (struct node **)*((char ***)0x40101380), *cur;
    int i;
    esf_buf_printf("esf_buf:");
    for (i = 0; i < 5; ++i) { // esf_buf 1, 4, 5, 6, esf_rx_buf (in order)
        esf_buf_printf(" [%d", i);
        for (cur = base[i]; cur; cur = (((size_t)cur) & 0x3) ? NULL : cur->next) {
            esf_buf_printf(" %p", cur);
        }
        esf_buf_printf("]");
    }
    esf_buf_printf("\n");
{
    struct block {
        struct block *next;
        size_t size;
    };
    size_t heap_size = system_get_free_heap_size();
    size_t *addr = (void *)0x3ffe9e38;
    int i;
    static struct block *cur = NULL;
    if (is_mem_error && cur) {
        esf_buf_printf("assert_heap: skipping heap search\n");
        goto found;
    }
    void *ptr = pvPortMalloc(1);
    vPortFree(ptr);
    for (i = -1000; i <= 1000; ++i) {
        if (addr[i] == heap_size) {
            int j;
            void **it = (void *)(addr + i);
            for (j = -10; j <= 10; ++j) {
                if ((((char *)ptr) - 128) <= (char *)it[j] && (char *)it[j] <= ((char *)ptr) + 128) {
                    if (((struct block *)(it + j))->size == 0) {
                        cur = (void *)(it + j);
                        goto found;
                    }
                }
            }
        }
    }
    assert(false /* no heap */);
found:;
#if 1
    USER_INTR_LOCK();
    esf_buf_printf("heap: %p size: %d stack: %p blocks:", cur, heap_size, &ptr);
    for (; cur != NULL && (3 & (size_t) cur) == 0; cur = cur->next) {
#if 1
        if (!(cur->size < 82000) && (cur->size + 65536 < 82000)) {
            esf_buf_printf(" fix:");
            cur->size += 65536;
        }
#endif
        size_t size = cur->size & ~(1 << (sizeof(size_t) * 8 - 1));
        assert((void **)cur < &ptr);
        if (size != cur->size) {
            esf_buf_printf(" used:");
        }
        esf_buf_printf(" [%d] %d", size, ((size_t)cur->next) - (((size_t)cur) + size));
        if (!(size < 82000) || !(cur->next > cur) || heap_size < size) {
            char *begin = ((char *)cur) - 1024, *end = ((char *)cur) + 1024;
            esf_buf_printf("mem[%p:%p]: ", begin, end);
            for (; begin != end; ++begin) {
                esf_buf_printf("%02x", *begin);
            }
            esf_buf_printf("\n");
        }
        assert(size <= 82000);
        assert(cur->next > cur);
        heap_size -= size;
        if (((int)heap_size) <= 0) {
            break;
        }
    }
    esf_buf_printf("\n");
    assert(heap_size == 0);
    USER_INTR_UNLOCK();
#endif
}
}

err_t __real_ip_input(struct pbuf *p, struct netif *inp);
ICACHE_FLASH_ATTR
err_t __wrap_ip_input(struct pbuf *p, struct netif *inp) {
    user_dprintf("%p %p", p, inp);
    assert(p->ref >= 1);
    assert(p->len < 2000);
    assert(p->tot_len < 2000);
#ifndef NDEBUG
    static int count = 0;
#endif
    assert(count++ == 0);
    assert_heap();
    err_t ret = __real_ip_input(p, inp);
    assert_heap();
    assert(--count == 0);
    if (ret != ERR_OK) {
        user_dprintf("ip_input: returned error %d", ret);
    }
    return ret;
}

ICACHE_FLASH_ATTR
static size_t debug_esp_get_intlevel() {
    size_t ps;
    __asm__ __volatile__("rsr %0, ps":"=r"(ps));
    assert(0 <= PS_INTLEVEL(ps) && PS_INTLEVEL(ps) <= XCHAL_NMILEVEL);
    return PS_INTLEVEL(ps);
}

ICACHE_FLASH_ATTR
void debug_esp_assert_not_nmi() {
    assert(debug_esp_get_intlevel() != XCHAL_NMILEVEL);
}

/**
 * Interrupt lock counters.
 * We set the NMI level to 0 because sometimes the interrupt level gets changed.
 */
size_t intr_lock_count[XCHAL_NMILEVEL] = {0}, intr_lock_count_sum = 0;

ICACHE_FLASH_ATTR
void debug_esp_check_intr_lock_count_sum() {
    int sum = 0, i;
    for (i = 0; i != XCHAL_NMILEVEL; ++i) {
        sum += intr_lock_count[i];
    }
    assert(sum == intr_lock_count_sum);
}

ICACHE_FLASH_ATTR
void debug_esp_user_intr_lock() {
    ets_intr_lock();
    assert(intr_lock_count[debug_esp_get_intlevel() % XCHAL_NMILEVEL]++ == intr_lock_count_sum++);
    debug_esp_check_intr_lock_count_sum();
}

ICACHE_FLASH_ATTR
void debug_esp_user_intr_unlock() {
    debug_esp_check_intr_lock_count_sum();
    assert(--intr_lock_count[debug_esp_get_intlevel() % XCHAL_NMILEVEL] == --intr_lock_count_sum);
    ets_intr_unlock();
}

#endif

#define WRAP_ALLOC(func, call, ...) \
void *__real_pvPort ## func; \
/* ICACHE_FLASH_ATTR (not used for original) */ \
void *__wrap_pvPort ## func { \
    void *ret = __real_pvPort ## call; \
    if (!ret) { \
        user_dprintf(__VA_ARGS__); \
        system_restart(); \
    } \
    return ret; \
}
#ifndef DEBUG_ESP
WRAP_ALLOC(Malloc(size_t size), Malloc(size), "malloc(%d) failed", size)
#endif
WRAP_ALLOC(Calloc(size_t n, size_t size), Calloc(n, size), "calloc(%d, %d) failed", n, size)
WRAP_ALLOC(Zalloc(size_t size), Zalloc(size), "zalloc(%d) failed", size)
WRAP_ALLOC(Realloc(void *ptr, size_t size), Realloc(ptr, size), "realloc(%p, %d) failed", ptr, size)
#undef WRAP_ALLOC

ICACHE_FLASH_ATTR
void debug_esp_fatal() {
    print_stack();
    gdb_stub_force_break();
    system_restart();
}
