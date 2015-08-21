#ifndef __CORO_H__
#define __CORO_H__

#include <setjmp.h>
#define setjmp __builtin_setjmp
#define longjmp __builtin_longjmp

struct coro_control {
    jmp_buf main, worker;
    size_t event;
    bool blocked;
};

#define CORO_T(stackwords) \
    struct { \
        struct coro_control ctrl; \
        char stack[(stackwords)*sizeof(size_t)]; \
    }

#define CORO_START(coro, func, arg) \
    do { \
        (coro).event = 0; \
        (coro).blocked = false; \
        ... \
    } while (0)

#define CORO_YIELD_OR(coro, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71, a72, a73, a74, a75, a76, a77, a78, a79, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a90, a91, a92, a93, a94, a95, a96, a97, a98, a99, a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a110, a111, a112, a113, a114, a115, a116, a117, a118, a119, a120, a121, a122, a123, a124, a125) ((1<<(uint8_t)(a0)) | (1<<(uint8_t)(a1)) | (1<<(uint8_t)(a2)) | (1<<(uint8_t)(a3)) | (1<<(uint8_t)(a4)) | (1<<(uint8_t)(a5)) | (1<<(uint8_t)(a6)) | (1<<(uint8_t)(a7)) | (1<<(uint8_t)(a8)) | (1<<(uint8_t)(a9)) | (1<<(uint8_t)(a10)) | (1<<(uint8_t)(a11)) | (1<<(uint8_t)(a12)) | (1<<(uint8_t)(a13)) | (1<<(uint8_t)(a14)) | (1<<(uint8_t)(a15)) | (1<<(uint8_t)(a16)) | (1<<(uint8_t)(a17)) | (1<<(uint8_t)(a18)) | (1<<(uint8_t)(a19)) | (1<<(uint8_t)(a20)) | (1<<(uint8_t)(a21)) | (1<<(uint8_t)(a22)) | (1<<(uint8_t)(a23)) | (1<<(uint8_t)(a24)) | (1<<(uint8_t)(a25)) | (1<<(uint8_t)(a26)) | (1<<(uint8_t)(a27)) | (1<<(uint8_t)(a28)) | (1<<(uint8_t)(a29)) | (1<<(uint8_t)(a30)) | (1<<(uint8_t)(a31)) | (1<<(uint8_t)(a32)) | (1<<(uint8_t)(a33)) | (1<<(uint8_t)(a34)) | (1<<(uint8_t)(a35)) | (1<<(uint8_t)(a36)) | (1<<(uint8_t)(a37)) | (1<<(uint8_t)(a38)) | (1<<(uint8_t)(a39)) | (1<<(uint8_t)(a40)) | (1<<(uint8_t)(a41)) | (1<<(uint8_t)(a42)) | (1<<(uint8_t)(a43)) | (1<<(uint8_t)(a44)) | (1<<(uint8_t)(a45)) | (1<<(uint8_t)(a46)) | (1<<(uint8_t)(a47)) | (1<<(uint8_t)(a48)) | (1<<(uint8_t)(a49)) | (1<<(uint8_t)(a50)) | (1<<(uint8_t)(a51)) | (1<<(uint8_t)(a52)) | (1<<(uint8_t)(a53)) | (1<<(uint8_t)(a54)) | (1<<(uint8_t)(a55)) | (1<<(uint8_t)(a56)) | (1<<(uint8_t)(a57)) | (1<<(uint8_t)(a58)) | (1<<(uint8_t)(a59)) | (1<<(uint8_t)(a60)) | (1<<(uint8_t)(a61)) | (1<<(uint8_t)(a62)))
#define CORO_YIELD(coro, ...) do { \
    (coro).event = CORO_YIELD_OR(##__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); \
    ... \
} while (0)

#define CORO_RESUME(coro, what_val) \
    do { \
        uint8_t what = (what_val); \
        if ((1<<(uint8_t)what) & (coro).event) { \
            (coro).event = what; \
            ... \
        } \
    } while (0)

#endif
