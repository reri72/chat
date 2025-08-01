#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "common.h"

void read_header(proto_hdr_t *hdr, char *buffer)
{
    memcpy(hdr, buffer, sizeof(proto_hdr_t));
    hdr->proto = ntohs(hdr->proto);
    hdr->bodylen = ntohl(hdr->bodylen);
}