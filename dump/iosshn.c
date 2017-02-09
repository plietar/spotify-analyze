#include <stdio.h>
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <assert.h>

#include "pcap.h"
#include "shn.h"

#define DIRECTION_SEND 0
#define DIRECTION_RECV 1

static int dump_fd;
static int hasOpened = 0;

static void initFile() {
    dump_fd = open("Replace with path to directory /dump.pcap", O_CREAT | O_RDWR | O_TRUNC, 0644);
    pcap_write_header(dump_fd, PCAP_DLT_USER0);
    printf("Dump file initialized\n");
}

static void my_shn_encrypt(UCHAR * buf, int nbytes) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pcap_write_packet_header(dump_fd, &tv, 1 + nbytes);

    uint8_t direction = DIRECTION_SEND;
    write(dump_fd, &direction, 1);
    write(dump_fd, buf, nbytes);
}

static void my_shn_decrypt(UCHAR * buf, int nbytes) {
    static struct {
        uint8_t cmd;
        uint16_t length;
    } __attribute__((packed)) header = { 0, 0 };

    if (header.cmd == 0) {
        assert(nbytes == 3);
        memcpy(&header, buf, 3);
    } else {
        assert(nbytes == ntohs(header.length));

        struct timeval tv;
        gettimeofday(&tv, NULL);
        pcap_write_packet_header(dump_fd, &tv, 4 + nbytes);

        uint8_t direction = DIRECTION_RECV;
        write(dump_fd, &direction, 1);
        write(dump_fd, &header, 3);
        write(dump_fd, buf, nbytes);

        header.cmd = 0;
    }
}

void sp_f2d2fa24b5944740acf40ea9f0fb352e (shn_ctx * c, UCHAR * buf, int nbytes) {
	if (!hasOpened) {
		initFile();
		hasOpened = 1;
	}
	my_shn_encrypt(buf, nbytes);
	shn_encrypt(c, buf, nbytes);
}

void sp_1e66e9e29aa743f3a4bfa4550da046fc (shn_ctx * c, UCHAR * buf, int nbytes) {
	shn_decrypt(c, buf, nbytes);
	my_shn_decrypt(buf, nbytes);
}

void sp_220e05475dd145729b07fb97feb11045 (shn_ctx * c, UCHAR * buf, int nbytes) {
	shn_finish(c, buf, nbytes);
}

void sp_4765711b05524eaba8b74b531b892fa4 (shn_ctx * c, const UCHAR *key, int keylen) {
    shn_key(c, key, keylen);
}

void sp_654f940627174249abb08c7051b7da5e (shn_ctx * c, const UCHAR *nonce, int noncelen) {
    shn_nonce(c, nonce, noncelen);
}
