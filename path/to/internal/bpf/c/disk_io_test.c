# complete code
#include <linux/bpf.h>
#include "kerno_test.h"

struct kerno_backpressure {
    __u32 should_emit;
};

SEC("classifier")
int kerno_backpressure_cls(struct xdp_md *ctx) {
    struct kerno_backpressure *backpressure = (struct kerno_backpressure *)ctx->data;
    if (backpressure->should_emit == 0) {
        return XDP_DROP;
    }
    return XDP_PASS;
}