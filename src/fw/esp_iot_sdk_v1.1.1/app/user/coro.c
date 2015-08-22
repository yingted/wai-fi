#include <user_config.h>
#include <coro.h>

#define setjmp __builtin_setjmp
#define longjmp __builtin_longjmp

__attribute__((returns_twice))
ICACHE_FLASH_ATTR
void coro_start_impl(struct coro_control *CORO_VOLATILE coro, size_t stacksize, void(*func)(void *), void *arg) {
    assert(coro->state == CORO_DEAD);
    assert(!coro->event); // initialized to false
    static void *volatile sp;
    if (!setjmp(coro->main)) {
        CORO_GOTO(coro, RESUME);

        register void *stack_top = coro->stack + stacksize;
        // Tell GCC we need to read from sp so it doesn't overlap it with stack_top
        __asm__ __volatile__("\
            mov %[sp], a1\n\
            mov a1, %[stack_top]\n\
        ":[sp] "+r"(sp):[stack_top] "r"(stack_top));
        (*func)(arg);
        __asm__ __volatile__("\
            mov a1, %[sp]\n\
        "::[sp] "r"(sp));

        assert(coro->state == CORO_RESUME);
        assert(!coro->event);
        CORO_GOTO(coro, DEAD);
    } else {
        __asm__ __volatile__("\
            mov a1, %[sp]\n\
        "::[sp] "r"(sp));

        assert(coro->state == CORO_YIELD);
        assert(coro->event);
    }
}

ICACHE_FLASH_ATTR
void coro_resume_impl(struct coro_control *coro, size_t what) {
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
}

ICACHE_FLASH_ATTR
void coro_yield_impl(struct coro_control *coro, size_t mask) {
    assert(mask);
    coro->event = mask;

    if (!setjmp(coro->worker)) {
        CORO_GOTO(coro, YIELD);
        longjmp(coro->main, 1);
    }
}
