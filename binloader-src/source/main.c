/*
  binloader — FW-independent ring3 payload receiver for the Sploithen 14.02 chain.

  Why this exists (worklog 2026-11-13): the direct payload path (fetch hen-1402.bin
  -> pthread) was tested on console and still fails at/after thread start. Every
  piece BEFORE the payload is proven good (15/15 kernel patches, uid 0, ring0 gate
  live, 220 handles defused), and the payload thread itself provably ran and reached
  ring0 (bug3.txt) — so raw syscalls, mmap RWX and pthread all work in the WebKit
  process on 14.02. This stub uses ONLY those proven primitives:

    - raw syscalls, no dlsym, no libSceNet, no GOT bootstrap, no module handles
    - socket(97) / setsockopt(105)  : proven on this console by afterglow's own
      S map (S.socket=97 used for the UAF reclaim sockets; setsockopt=105 likewise)
    - close(6), mmap(477), munmap(73), mprotect(74) : SDK libPS4 memory.c SYSCALL
      table == afterglow's console-proven S.mmap/S.mprotect/S.close
    - bind(104), listen(106), accept(30), recvfrom(29) : FreeBSD-9 base syscall
      slots that PS4 kept (same table that gives kill=37, ptrace=108, evf=540+,
      dynlib=592+, mmap=477). A wrong number can only return an error, never
      corrupt anything.

  Protocol (community-standard binloader):
    - stub listens on TCP 9020 on all interfaces
    - PC sends a raw payload blob and CLOSES the connection
      (nc -q0 <PS4-IP> 9020 < payload.bin  /  any injector that closes after send)
    - stub receives until EOF, validates the blob starts with 0xE9 (the raw
      payload convention used by this whole chain), mmaps RWX (payload + a zero
      tail for the mmap-tail GOT convention), copies, jumps to the entry with
      arg=0 — the exact convention the host loader itself uses
      (afterglow loadPayload: pthread_create(&thr, 0, entry, 0)).
    - when the payload RETURNS (e.g. "Unsupported Firmware" notify path), the
      stub re-listens: payloads can be pushed one after another without
      reloading the page. A probe connection that opens+closes immediately is
      simply discarded as an empty payload.
*/

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef long long      s64;

/* ---- raw syscall shims (fixed arity; 4th arg rcx -> r10; CF set + errno on error) ---- */

__asm__(".intel_syntax noprefix\n"
        ".text\n"

        /* long _sys_socket(int domain, int type, int protocol)  -- 97 */
        ".globl _sys_socket\n"
        "_sys_socket:\n"
        "  mov eax, 97\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_close(int fd)  -- 6 */
        ".globl _sys_close\n"
        "_sys_close:\n"
        "  mov eax, 6\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* long _sys_recvfrom(int fd, void* buf, u64 len, int flags, void* from, u64* fromlen)  -- 29 */
        ".globl _sys_recvfrom\n"
        "_sys_recvfrom:\n"
        "  mov eax, 29\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_accept(int fd, void* addr, u64* addrlen)  -- 30 */
        ".globl _sys_accept\n"
        "_sys_accept:\n"
        "  mov eax, 30\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_setsockopt(int fd, int level, int opt, void* val, u32 len)  -- 105 */
        ".globl _sys_setsockopt\n"
        "_sys_setsockopt:\n"
        "  mov eax, 105\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_bind(int fd, void* addr, int addrlen)  -- 104 */
        ".globl _sys_bind\n"
        "_sys_bind:\n"
        "  mov eax, 104\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_listen(int fd, int backlog)  -- 106 */
        ".globl _sys_listen\n"
        "_sys_listen:\n"
        "  mov eax, 106\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_mprotect(u64 addr, u64 len, int prot)  -- 74 */
        ".globl _sys_mprotect\n"
        "_sys_mprotect:\n"
        "  mov eax, 74\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_munmap(u64 addr, u64 len)  -- 73 */
        ".globl _sys_munmap\n"
        "_sys_munmap:\n"
        "  mov eax, 73\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* u64 _sys_mmap(u64 addr, u64 len, int prot, int flags, int fd, s64 off)  -- 477 */
        ".globl _sys_mmap\n"
        "_sys_mmap:\n"
        "  mov eax, 477\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* error path: syscall returned with CF=1 and eax=errno -> return -errno.
           Must sign-extend into the 64-bit domain FIRST: a bare `neg eax`
           zero-extends into rax and would come back as a huge positive value. */
        "9:\n"
        "  movsxd rax, eax\n"
        "  neg rax\n"
        "  ret\n");

extern int  _sys_socket(int domain, int type, int protocol);
extern int  _sys_close(int fd);
extern long _sys_recvfrom(int fd, void *buf, u64 len, int flags, void *from, u64 *fromlen);
extern int  _sys_accept(int fd, void *addr, u64 *addrlen);
extern int  _sys_setsockopt(int fd, int level, int opt, void *val, u32 len);
extern int  _sys_bind(int fd, void *addr, int addrlen);
extern int  _sys_listen(int fd, int backlog);
extern int  _sys_mprotect(u64 addr, u64 len, int prot);
extern int  _sys_munmap(u64 addr, u64 len);
extern u64  _sys_mmap(u64 addr, u64 len, int prot, int flags, int fd, s64 off);

/* freestanding fallbacks: satisfy any implicit memcpy/memset gcc may emit and
   nothing else (CFLAGS add -fno-tree-loop-distribute-patterns so these bodies
   cannot be "optimised" into calls to themselves). */
void *memcpy(void *dst, const void *src, u64 n) {
  u8 *d = (u8 *)dst; const u8 *s = (const u8 *)src;
  while (n) { *d++ = *s++; n--; }
  return dst;
}
void *memset(void *dst, int c, u64 n) {
  u8 *d = (u8 *)dst;
  while (n) { *d++ = (u8)c; n--; }
  return dst;
}

/* ---- config ---- */
#define BINLOADER_PORT   9020          /* community-standard binloader port */
#define STAGE_MAX        (8u * 1024u * 1024u)   /* staging buffer: 8 MiB */
#define TAIL_PAD         0x40000u      /* zero tail behind the payload image --
                                          same +0x40000 the host loader mmaps for
                                          the mmap-tail GOT convention */
#define MIN_PAYLOAD      16

/* FreeBSD sockaddr_in, 16 bytes: len, family, port(be), addr, zero[8] */
struct sa_in {
  u8  len;
  u8  family;
  u16 port_be;
  u32 addr;
  char zero[8];
};

#define AF_INET        2
#define SOCK_STREAM    1
#define SOL_SOCKET     0xffff
#define SO_REUSEADDR   4
#define PROT_RW        3              /* read|write */
#define PROT_RWX       7              /* read|write|exec (console-proven: the
                                          loader itself mprotects 7 on this FW) */
#define MAP_ANON_PRIVATE 0x1002       /* MAP_ANON|MAP_PRIVATE -- afterglow's own value */

static void byte_copy(u64 dst, u64 src, u64 n) {
  u8 *d = (u8 *)dst; const u8 *s = (const u8 *)src;
  while (n) { *d++ = *s++; n--; }
}

int _main(void *args) {
  (void)args;

  /* staging buffer, RW only, mapped once for the thread's lifetime */
  u64 stage = _sys_mmap(0, STAGE_MAX, PROT_RW, MAP_ANON_PRIVATE, -1, 0);
  if ((s64)stage < 0) return -1;

  for (;;) {
    /* listener socket; re-created per payload so re-listen is always clean */
    int sfd = _sys_socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return -2;

    int one = 1;
    _sys_setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sa_in sa;
    sa.len     = (u8)sizeof(sa);          /* 16 */
    sa.family  = AF_INET;
    sa.port_be = (u16)(((BINLOADER_PORT & 0xFFu) << 8) | ((BINLOADER_PORT >> 8) & 0xFFu));
    sa.addr    = 0;                        /* INADDR_ANY */
    for (int i = 0; i < 8; i++) sa.zero[i] = 0;

    if (_sys_bind(sfd, &sa, (int)sizeof(sa)) < 0) { _sys_close(sfd); return -3; }
    if (_sys_listen(sfd, 4) < 0)                  { _sys_close(sfd); return -4; }

    int cfd = _sys_accept(sfd, 0, 0);
    if (cfd < 0) { _sys_close(sfd); continue; }

    /* receive until the sender closes (nc -q0 / injectors close after send) */
    u64 total = 0;
    for (;;) {
      u64 room = STAGE_MAX - total;
      if (room == 0) break;               /* over 8 MiB: caller's problem, documented */
      long n = _sys_recvfrom(cfd, (void *)(stage + total), room, 0, 0, 0);
      if (n <= 0) break;                  /* 0 = clean EOF; <0 = error */
      total += (u64)n;
    }
    _sys_close(cfd);
    _sys_close(sfd);

    /* validate: raw payload convention (starts with jmp, sane size) */
    if (total < MIN_PAYLOAD || ((u8 *)stage)[0] != 0xE9) continue;  /* re-listen */

    /* exec image: payload bytes + zero tail (GOT slots live there), page-rounded
       the same way the host loader rounds (size & ~0x3fff) */
    u64 esz = (total + TAIL_PAD + 0x3FFFu) & ~(u64)0x3FFFu;
    u64 ex  = _sys_mmap(0, esz, PROT_RW, MAP_ANON_PRIVATE, -1, 0);
    if ((s64)ex < 0) continue;

    byte_copy(ex, stage, total);
    if (_sys_mprotect(ex, esz, PROT_RWX) != 0) { _sys_munmap(ex, esz); continue; }

    /* same call convention as the host loader: pthread_create(fn=entry, arg=0).
       Runs synchronously on THIS thread; when the payload returns, we serve the
       next one. */
    void *(*entry)(void *) = (void *(*)(void *))ex;
    entry((void *)0);

    _sys_munmap(ex, esz);
    /* loop: accept the next payload */
  }

  /* not reached */
  _sys_munmap(stage, STAGE_MAX);
  return 0;
}
