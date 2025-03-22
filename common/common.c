#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "common.h"

void read_header(proto_hdr_t *hdr, unsigned char *buffer)
{
    memcpy(hdr, buffer, sizeof(proto_hdr_t));
    hdr->flag = ntohs(hdr->flag);
    *buffer += sizeof(proto_hdr_t);
}