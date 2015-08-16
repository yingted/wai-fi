#ifndef __DEBUG_ESP_H__
#define __DEBUG_ESP_H__

#include <xtensa/config/core-isa.h>

#ifndef NDEBUG
void print_stack();
#define print_stack_once() do { \
    static bool printed = 0; \
    if (printed) \
        break; \
    printed = 1; \
    print_stack(); \
} while (0)
#endif

#ifdef DEBUG_ESP

#define assert_heap() assert_heap_(__FILE__, __LINE__)
void assert_heap_(char *file, int line);
void show_esf_buf();
void mem_error();
void debug_esp_install_exc_handler();

#define pvPortMalloc __real_pvPortMalloc
#define inet_chksum_pseudo __real_inet_chksum_pseudo
#define inet_chksum_pseudo_partial __real_inet_chksum_pseudo_partial
#define inet_chksum __real_inet_chksum
#define inet_chksum_pbuf __real_inet_chksum_pbuf
#define mem_malloc __real_mem_malloc
#define mem_realloc __real_mem_realloc

extern size_t intr_lock_count[XCHAL_NMILEVEL], intr_lock_count_sum;
void debug_esp_user_intr_lock();
void debug_esp_user_intr_unlock();
void debug_esp_assert_not_nmi();

#else

#define assert_heap()
#define show_esf_buf()
#define mem_error()
#define debug_esp_install_exc_handler()
#define debug_esp_assert_not_nmi()

#endif

void debug_esp_fatal();

#endif
