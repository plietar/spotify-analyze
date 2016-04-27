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

/*
 * First 64 bytes of shn_encrypt and shn_decrypt.
 * Used to locate these functions in the binary.
 * Hoping these won't change in future version.
 */
const uint8_t SHN_ENCRYPT_SIGNATURE[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
    0x41, 0x54, 0x53, 0x8b, 0x87, 0xcc, 0x00, 0x00,
    0x00, 0x85, 0xc0, 0x0f, 0x84, 0xac, 0x00, 0x00,
    0x00, 0x85, 0xd2, 0x0f, 0x84, 0x58, 0x0d, 0x00,
    0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2e,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x1e, 0xb9, 0x20, 0x00, 0x00, 0x00,
    0x29, 0xc1, 0xd3, 0xe3, 0x31, 0x9f, 0xc8, 0x00,
};

const uint8_t SHN_DECRYPT_SIGNATURE[] = {
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
    0x41, 0x55, 0x41, 0x54, 0x53, 0x8b, 0x87, 0xcc,
    0x00, 0x00, 0x00, 0x85, 0xc0, 0x0f, 0x84, 0xb3,
    0x00, 0x00, 0x00, 0x85, 0xd2, 0x0f, 0x84, 0xa3,
    0x0e, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x2e,
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x8b, 0x9f, 0xc4, 0x00, 0x00, 0x00, 0xb9, 0x20,
    0x00, 0x00, 0x00, 0x29, 0xc1, 0xd3, 0xeb, 0x0f,
};

void patch_function(void *src, const void *dst);

#define DIRECTION_SEND 0
#define DIRECTION_RECV 1

static int dump_fd;

static void my_shn_encrypt(shn_ctx * c, UCHAR * buf, int nbytes) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pcap_write_packet_header(dump_fd, &tv, 1 + nbytes);

    uint8_t direction = DIRECTION_SEND;
    write(dump_fd, &direction, 1);
    write(dump_fd, buf, nbytes);

    shn_encrypt(c, buf, nbytes);
}

static void my_shn_decrypt(shn_ctx * c, UCHAR * buf, int nbytes) {
    shn_decrypt(c, buf, nbytes);

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

static void find_and_patch(const char *name,
                           void *text_start, size_t text_size,
                           const void *signature, size_t signature_size,
                           const void *replacement) {

    void *original = memmem(text_start, text_size, signature, signature_size);

    if (original == NULL) {
        printf("%s: not found\n", name);
        exit(1);
    } else {
        printf("%s: %p\n", name, original);
    }

    patch_function(original, replacement);
}

static void patch_shn(void) {
    dump_fd = open("dump.pcap", O_CREAT | O_RDWR | O_TRUNC, 0644);

    pcap_write_header(dump_fd, PCAP_DLT_USER0);

    printf("Patching ...\n");

    uintptr_t aslr_offset = _dyld_get_image_vmaddr_slide(0);
    printf("ASLR slide: 0x%lx\n", aslr_offset);

    size_t text_size;
    void *text_start = getsectdata("__TEXT", "__text", &text_size) + aslr_offset;
    printf("text: %p size=0x%zx\n", text_start, text_size);

    find_and_patch("shn_encrypt",
                   text_start, text_size,
                   SHN_ENCRYPT_SIGNATURE, sizeof(SHN_ENCRYPT_SIGNATURE),
                   my_shn_encrypt);

    find_and_patch("shn_decrypt",
                   text_start, text_size,
                   SHN_DECRYPT_SIGNATURE, sizeof(SHN_DECRYPT_SIGNATURE),
                   my_shn_decrypt);
}

/*
 * connect() is called concurrently by multiple threads.
 * Ensure we only inject our code once.
 */
pthread_once_t patch_once = PTHREAD_ONCE_INIT;
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    pthread_once(&patch_once, patch_shn);
    return connect(sockfd, addr, addrlen);
}

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee }

DYLD_INTERPOSE(my_connect, connect);

// From subhook: https://github.com/Zeex/subhook
#define PUSH_OPCODE 0x68
#define MOV_OPCODE  0xC7
#define RET_OPCODE  0xC3

#define MOV_MODRM_BYTE 0x44 /* write to address + 1 byte displacement */
#define MOV_SIB_BYTE   0x24 /* write to [rsp] */
#define MOV_OFFSET     0x04

struct jmp64 {
    uint8_t  push_opcode;
    uint32_t push_addr; /* lower 32-bits of the address to jump to */
    uint8_t  mov_opcode;
    uint8_t  mov_modrm;
    uint8_t  mov_sib;
    uint8_t  mov_offset;
    uint32_t mov_addr;  /* upper 32-bits of the address to jump to */
    uint8_t  ret_opcode;
} __attribute__((packed));

void unprotect(void *address) {
    long pagesize = sysconf(_SC_PAGESIZE);

    address = (void *)((long)address & ~(pagesize - 1));

    mprotect(address, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void patch_function(void *src, const void *dst) {
    unprotect(src);

    struct jmp64 *jmp = (struct jmp64 *)src;

    jmp->push_opcode = PUSH_OPCODE;
    jmp->push_addr = (uint32_t)(uintptr_t)dst;
    jmp->mov_opcode = MOV_OPCODE;
    jmp->mov_modrm = MOV_MODRM_BYTE;
    jmp->mov_sib = MOV_SIB_BYTE;
    jmp->mov_offset = MOV_OFFSET;
    jmp->mov_addr = (uint32_t)(((uintptr_t)dst) >> 32);
    jmp->ret_opcode = RET_OPCODE;
}
