/* proto_dccp.c - stubbed for macOS BPF port */
#include <stddef.h>
#include "protos.h"
#include "proto.h"


struct protocol dccp_ops = {
    .key = 0x0021,
    .print_full = NULL,
    .print_less = NULL,
};
