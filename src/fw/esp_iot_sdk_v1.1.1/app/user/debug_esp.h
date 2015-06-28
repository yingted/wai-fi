#ifndef __DEBUG_ESP_H__
#define __DEBUG_ESP_H__

#ifdef DEBUG_ESP
extern size_t icmp_net_lwip_entry_count;

#define assert_heap() assert_heap_(__FILE__, __LINE__)
void assert_heap_(char *file, int line);
void show_esf_buf();
void mem_error();

#define pvPortMalloc __real_pvPortMalloc
#define inet_chksum_pseudo __real_inet_chksum_pseudo
#define inet_chksum_pseudo_partial __real_inet_chksum_pseudo_partial
#define inet_chksum __real_inet_chksum
#define inet_chksum_pbuf __real_inet_chksum_pbuf
#define mem_malloc __real_mem_malloc
#define mem_realloc __real_mem_realloc

#else

#define assert_heap()
#define show_esf_buf()
#define mem_error()

#endif

#endif
