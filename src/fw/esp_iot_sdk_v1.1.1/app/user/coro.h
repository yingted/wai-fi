#ifndef __CORO_H__
#define __CORO_H__

#define __XTENSA_WINDOWED_ABI__ 0
#include <setjmp.h>

struct coro_control {
    /**
     * Saved registers
     */
    jmp_buf main, worker;
    /**
     * Event(s), as a mask. 3 cases:
     * 1. Yielding for an event: any non-zero mask
     * 2. Resuming with an event: a power of 2
     * 3. Not blocked: 0
     */
    size_t event;
    char stack[0];
#ifndef NDEBUG
    enum {
        CORO_DEAD,
        CORO_YIELD,
        CORO_RESUME,
    } state;
#define CORO_GOTO(ctrl, new_state) ((ctrl)->state = CORO_ ## new_state)
#else
#define CORO_GOTO(...)
#endif
};

#ifndef NDEBUG
#define CORO_VOLATILE volatile
#else
#define CORO_VOLATILE
#endif
void coro_start_impl(struct coro_control *CORO_VOLATILE coro, size_t stacksize, void(*func)(void *), void *arg);
void coro_resume_impl(struct coro_control *coro, size_t what);
void coro_yield_impl(struct coro_control *coro, CORO_VOLATILE size_t mask);

#define CORO_T(stackwords) \
    struct { \
        struct coro_control ctrl; \
        char stack[(stackwords)*sizeof(size_t)]; \
    }

#define CORO_START(coro, func, arg) \
    coro_start_impl(&(coro).ctrl, sizeof((coro).stack), (func), (arg))

#define CORO_YIELD_OR_(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, ...) ((a0) | (a1) | (a2) | (a3) | (a4) | (a5) | (a6) | (a7) | (a8) | (a9) | (a10) | (a11) | (a12) | (a13) | (a14) | (a15) | (a16) | (a17) | (a18) | (a19) | (a20) | (a21) | (a22) | (a23) | (a24) | (a25) | (a26) | (a27) | (a28) | (a29) | (a30) | (a31) | (a32) | (a33) | (a34) | (a35) | (a36) | (a37) | (a38) | (a39) | (a40) | (a41) | (a42) | (a43) | (a44) | (a45) | (a46) | (a47) | (a48) | (a49) | (a50) | (a51) | (a52) | (a53) | (a54) | (a55) | (a56) | (a57) | (a58) | (a59) | (a60) | (a61) | (a62) | (a63))
#define CORO_YIELD(coro, ...) \
    coro_yield_impl(&(coro).ctrl, CORO_YIELD_OR_(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

#define CORO_RESUME(coro, what_val) \
    coro_resume_impl(&(coro).ctrl, what_val)

#endif
