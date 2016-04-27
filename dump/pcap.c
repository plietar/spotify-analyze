#include "pcap.h"

#include <unistd.h>

void pcap_write_header(int fd, uint32_t network) {
    pcap_hdr_t hdr = {
        .magic_number = PCAP_MAGIC,
        .version_major = PCAP_MAJOR,
        .version_minor = PCAP_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = network,
    };
    write(fd, &hdr, sizeof(hdr));
}

void pcap_write_packet_header(int fd, const struct timeval *tv, uint32_t length) {
    pcaprec_hdr_t hdr = {
        .ts_sec = 0,
        .ts_usec = 0,
        .incl_len = length,
        .orig_len = length,
    };

    if (tv != NULL) {
        hdr.ts_sec = tv->tv_sec;
        hdr.ts_usec = tv->tv_usec;
    }

    write(fd, &hdr, sizeof(hdr));
}

