#include <user_config.h>
#include <coro.h>
#define __XTENSA_WINDOWED_ABI__ 0
#include <setjmp.h>

#define setjmp __builtin_setjmp
#define longjmp __builtin_longjmp

#ifndef NDEBUG
#define VOLATILE volatile
#else
#define VOLATILE
#endif

__attribute__((returns_twice))
ICACHE_FLASH_ATTR
void coro_start_impl(struct coro_control *VOLATILE coro, size_t stacksize, void(*func)(void *), void *arg) {
    assert(coro->state == CORO_DEAD);
    assert(!coro->event); // initialized to false
    if (!setjmp(coro->main)) {
        CORO_GOTO(coro, RESUME);

        static void *volatile sp;
        register void *stack_top = coro->stack + stacksize;
        __asm__ __volatile__("\
            mov %[sp], a1\n\
            mov a1, %[stack_top]\n\
        ":[sp] "=r"(sp):[stack_top] "r"(stack_top));
        (*func)(arg);
        __asm__ __volatile__("\
            mov a1, %[sp]\n\
        "::[sp] "r"(sp));

        assert(coro->state == CORO_RESUME);
        assert(!coro->event);
        CORO_GOTO(coro, DEAD);
    } else {
        assert(coro->state == CORO_YIELD);
        assert(coro->event);
    }
}

ICACHE_FLASH_ATTR
void coro_resume_impl(struct coro_control *coro, uint8_t what) {
    assert(coro->event);
    assert(what);
    assert((what & -what) == what);
    if (!(what & coro->event)) {
        return;
    }
    coro->event = what;

    if (!setjmp(coro->main)) {
        CORO_GOTO(coro, RESUME);
        longjmp(coro->worker, 1);
    }

    assert(coro->state == CORO_YIELD);
    assert(coro->event);
}

ICACHE_FLASH_ATTR
void coro_yield_impl(struct coro_control *coro, VOLATILE size_t mask) {
    coro->event = mask;

    if (!setjmp(coro->worker)) {
        CORO_GOTO(coro, YIELD);
        longjmp(coro->main, 1);
    }

    assert(coro->state == CORO_RESUME);
    assert(coro->event & mask);
}
