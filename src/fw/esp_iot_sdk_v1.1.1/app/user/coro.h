#ifndef __CORO_H__
#define __CORO_H__

#include <debug_esp.h>

struct coro_control {
    /**
     * Event(s), as a mask. 3 cases:
     * 1. Yielding for an event: any non-zero mask
     * 2. Resuming with an event: a power of 2
     * 3. Not blocked: 0
     */
    size_t event;
#ifndef NDEBUG
    // Check state transitions (start(), yield(), resume(), ..., return)
    // Added benefit of checking for stack corruption
    enum {
        CORO_DEAD,
        CORO_YIELD,
        CORO_RESUME,
    } state;
#define CORO_GOTO(coro, new_state) ((coro).state = CORO_ ## new_state)
#else
#define CORO_GOTO(...)
#endif
};

typedef struct coro_control coro_t;

typedef void *coro_label_t;

#define CORO_LABEL_IMPL_LABEL(line, counter) coro_label_line_ ## line ## _counter_ ## counter

#define CORO_LABEL_IMPL(line, counter) \
    do { \
        coro_label_next = &&CORO_LABEL_IMPL_LABEL(line, counter); \
        return; \
        CORO_LABEL_IMPL_LABEL(line, counter):; \
    } while (0)

#define CORO_LABEL() CORO_LABEL_IMPL(__LINE__, __COUNTER__)

#define CORO_BEGIN() \
    static coro_label_t coro_label_next = &&coro_label_ ## __LINE__ ## _begin; \
    goto *coro_label_next; \
    coro_label_ ## __LINE__ ## _begin:

#define CORO_END() CORO_LABEL()

#define CORO_START(coro, func) \
    do { \
        debug_esp_assert_interruptible(); \
        assert((coro).state == CORO_DEAD); \
        assert((coro).event == 0); \
        CORO_GOTO((coro), RESUME); \
        user_dprintf("CORO_START(" #func ")"); \
        (func)(); \
        assert((coro).state == CORO_YIELD); \
    } while (0)

#define CORO_YIELD_OR_(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, ...) ((a0) | (a1) | (a2) | (a3) | (a4) | (a5) | (a6) | (a7) | (a8) | (a9) | (a10) | (a11) | (a12) | (a13) | (a14) | (a15) | (a16) | (a17) | (a18) | (a19) | (a20) | (a21) | (a22) | (a23) | (a24) | (a25) | (a26) | (a27) | (a28) | (a29) | (a30) | (a31) | (a32) | (a33) | (a34) | (a35) | (a36) | (a37) | (a38) | (a39) | (a40) | (a41) | (a42) | (a43) | (a44) | (a45) | (a46) | (a47) | (a48) | (a49) | (a50) | (a51) | (a52) | (a53) | (a54) | (a55) | (a56) | (a57) | (a58) | (a59) | (a60) | (a61) | (a62) | (a63))
#define CORO_YIELD(coro, ...) \
    do { \
        debug_esp_assert_interruptible(); \
        assert((coro).state == CORO_RESUME); \
        (coro).event = CORO_YIELD_OR_(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); \
        assert((coro).event); \
        CORO_GOTO((coro), YIELD); \
        CORO_LABEL(); \
        assert((coro).state == CORO_RESUME); \
    } while (0)

#define CORO_RESUME(coro, what_val) \
    do { \
        debug_esp_assert_interruptible(); \
        assert((coro).event); \
        const size_t what = (what_val); \
        assert(what); \
        assert((coro).state == CORO_YIELD); \
        assert((what & -what) == what); \
        if (what & (coro).event) { \
            (coro).event = what; \
            CORO_GOTO((coro), RESUME); \
            (connmgr_init_impl)(); /* XXX */ \
            assert((coro).state == CORO_YIELD); \
        } \
    } while (0)

#endif
