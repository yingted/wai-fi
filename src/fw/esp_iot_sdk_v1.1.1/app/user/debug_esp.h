#ifndef __DEBUG_ESP_H__
#define __DEBUG_ESP_H__

#ifdef DEBUG_ESP
extern size_t icmp_net_lwip_entry_count;

#define assert_heap() assert_heap_(__FILE__, __LINE__)
void assert_heap_(char *file, int line);
void show_esf_buf();
void mem_error();

#else

#define assert_heap()
#define show_esf_buf()
#define mem_error()

#endif

#endif
