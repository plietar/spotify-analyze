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

static void patch_function(void *src, const void *dst);
static void *memrmem(const void *haystack, size_t haystack_size,
                     const void *needle, size_t needle_size);

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

static const uint8_t SHN_CONSTANT[] = { 0x3a, 0xc5, 0x96, 0x69 };
static const uint8_t PROLOGUE[] = { 0x55, 0x48, 0x89, 0xe5 };

/*
 * Basic heuristic to find shn_encrypt and shn_decrypt.
 * This should be fairly resistent to different spotify client versions.
 *
 * Locate the last occurence of the shn constant
 * Walk back and find function prologues
 * The first one is shn_finish (it contains the constant)
 * The second one is shn_decrypt.
 * The third one is shn_encrypt.
 */
static void find_shn_heuristic(void *text_start, size_t text_size, void **p_shn_encrypt, void ** p_shn_decrypt) {
    void *search_end = memrmem(text_start, text_size, SHN_CONSTANT, sizeof(SHN_CONSTANT));
    if (search_end == NULL) {
        printf("Could not find shn constant\n");
        exit(1);
    }

    search_end = memrmem(text_start, search_end - text_start, PROLOGUE, sizeof(PROLOGUE));
    assert(search_end != NULL);

    *p_shn_decrypt = search_end = memrmem(text_start, search_end - text_start, PROLOGUE, sizeof(PROLOGUE));
    assert(search_end != NULL);

    *p_shn_encrypt = search_end = memrmem(text_start, search_end - text_start, PROLOGUE, sizeof(PROLOGUE));
    assert(search_end != NULL);
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

    void *original_shn_encrypt, *original_shn_decrypt;
    find_shn_heuristic(text_start, text_size, &original_shn_encrypt, &original_shn_decrypt);

    printf("shn_encrypt: %p\n", original_shn_encrypt);
    printf("shn_decrypt: %p\n", original_shn_decrypt);

    patch_function(original_shn_encrypt, my_shn_encrypt);
    patch_function(original_shn_decrypt, my_shn_decrypt);
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

static void unprotect(void *address) {
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

static void *memrmem(const void *haystack, size_t haystack_size,
                     const void *needle, size_t needle_size) {
    if (haystack_size < needle_size)
        return NULL;
    if (needle_size == 0)
        return (void *) haystack + haystack_size;

    const void *p;
    for (p = haystack + haystack_size - needle_size; haystack_size >= needle_size; --p, --haystack_size) {
        if (memcmp(p, needle, needle_size) == 0) {
            return (void *) p;
        }
    }
    return NULL;
}

