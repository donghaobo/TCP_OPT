#ifndef __XT_TCPOPTADD_H__
#define __XT_TCPOPTADD_H__

#include <linux/types.h>

struct xt_tcpoptadd_info {
    int replace;
    int shrink;
    int opt_len;
    uint8_t opt[40];
};

#endif /* __XT_TCPOPTADD_H__ */
