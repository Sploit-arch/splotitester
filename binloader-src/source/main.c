/*
  binloader -- FW-independent ring3 payload receiver for the akatsuki 14.02 chain.

  Why this exists (worklog 2026-11-13): the direct payload path (fetch hen-1402.bin
  -> pthread) was tested on console and still fails at/after thread start. Every
  piece BEFORE the payload is proven good (15/15 kernel patches, uid 0, ring0 gate
  live, 220 handles defused), and the payload thread itself provably ran and reached
  ring0 (bug3.txt) -- so raw syscalls, mmap RWX and pthread all work in the WebKit
  process on 14.02. This stub uses ONLY those proven primitives.

  v3 changes (2026-11-13 round 3, evidence-driven):
    - REMOVED loadModule (syscall 594) ENTIRELY. v2's popup resolved
      sceKernelSendNotificationRequest by dynlib_load_prx of libkernel.sprx /
      libkernel_web.sprx / libkernel_sys.sprx -- the only module-loading
      operation in the whole chain, run BEFORE the HEN installer's own
      initKernel. Console evidence (this round's log): [hen] 1 entry was the
      LAST beacon, i.e. the installer died inside initKernel/initLibc -- the
      exact window that is console-PROVEN good since the bug3-era run, where
      nothing had loaded modules before it. The stub's load chain is the prime
      suspect, so it is gone: the stub must not touch dynlib_load_prx at all.
    - Notification popup now uses the RAW DEVICE PATH, zero libkernel
      interaction: open("/dev/notification0") + write(SceNotificationRequest)
      + close. Researched this round (worklog): sceKernelSendNotificationRequest
      itself just opens /dev/notification[0-5] and writes the 0xC30-byte request;
      the kernel forwards notification0/1 to SceShellUI, which renders the
      popup -- the same mechanism GoldHEN-style notifications use
      (OSM-Made/PS4-Notify: struct layout, Message type = 0, target_id = -1,
      has_icon = 1, icon uri "cxml://psnotification/tex_icon_system"; open
      flags FNONBLOCK). open=5 / write=4 / close=6 are the same FreeBSD-9
      base slots the SDK itself uses (libPS4 file.c: SYSCALL(open,5),
      SYSCALL(write,4)).
    - dlsym(591) fallback kept but now resolve-by-ENUMERATION only:
      getLoadedModules(592) lists the ALREADY-LOADED module handles and we
      dlsym each for "sceKernelSendNotificationRequest" -- no module is ever
      loaded, mapped or initialized by this stub.
    - Every notify step beacons its return code ("[bld] n0 ...") so the next
      console run proves exactly why a popup did or did not show.
    - Popup texts carry no dashes at all (user request): "binloader listening
      on port 9020" / "binloader executing payload".

  v4 changes (2026-11-12 round 4, user report + source evidence):
    - USER REPORT: a scene ELF64 payload sent to :9020 "didn't crash, just
      didn't work". Source evidence: v3's validation `((u8*)stage)[0] != 0xE9`
      silently DISCARDED every ELF blob (ELF magic is 7F 45 4C 46, first byte
      0x7F != 0xE9 -> continue -> re-listen, no beacon at all). The raw-only
      check is why ELF payloads never executed -- and, on its own, explains
      that symptom exactly.
    - v4 accepts BOTH payload formats: 0xE9 first byte = raw payload
      (unchanged path), 7F 45 4C 46 = ELF64 payload (new loader path),
      anything else = one honest "x unknown format" beacon + re-listen.
      "2 payload received" now beacons for BOTH formats.
    - ELF64 loader implemented against MEASURED facts of an SDK-built ELF
      (hello.elf, readelf this round): ET_DYN, base-0 vaddrs, entry 0x0, four
      PT_LOADs (bss memsz > filesz), align 0x1000, ZERO relocations, no
      PT_INTERP, no GOT/PLT (every symbol is a .bss function pointer filled
      by the payload's own initKernel/initLibc -- same SDK the HEN installer
      is built with; installer.map confirms .text at 0x0). Loading: parse
      Ehdr/Phdrs byte-explicitly (no struct alignment assumptions), place each
      PT_LOAD at base+(p_vaddr-min_vaddr), zero p_memsz, apply R_X86_64_
      RELATIVE relocations if PT_DYNAMIC carries DT_RELA (any other reloc
      type = honest refusal), enter at base+(e_entry-min_vaddr) with rdi=0 --
      the same convention the raw path uses. Every step beacons (e1..e6),
      every refusal beacons (x! ...) with the reason.

  Protocol (community-standard binloader):
    - stub listens on TCP 9020 on all interfaces
    - PC sends a raw payload blob and CLOSES the connection
      (nc --send-only <PS4-IP> 9020 < payload.bin for Ncat,
       nc -q0 <PS4-IP> 9020 < payload.bin for OpenBSD nc)
    - stub receives until EOF, then dispatches on the first bytes:
      0xE9        = raw payload (the convention this whole chain uses,
                    hen-1402.bin included) -> mmap RWX (payload + a zero tail
                    for the mmap-tail GOT convention), copy, jump to entry
                    with arg=0 -- the exact convention the host loader itself
                    uses (afterglow loadPayload: pthread_create(&thr,0,entry,0))
      7F 45 4C 46 = ELF64 payload (scene-standard binloader payloads,
                    hello.elf test payload included) -> full ELF64 loader (v4)
      anything else = honest "x unknown format" beacon, re-listen
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

        /* int _sys_connect(int fd, void* addr, int addrlen)  -- 98
           console-proven number: afterglow's own binloader reachability probe */
        ".globl _sys_connect\n"
        "_sys_connect:\n"
        "  mov eax, 98\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* long _sys_write(int fd, const void* buf, u64 len)  -- 4 */
        ".globl _sys_write\n"
        "_sys_write:\n"
        "  mov eax, 4\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_open(const char* path, int flags, int mode)  -- 5
           SDK libPS4 file.c: SYSCALL(open, 5) -- same FreeBSD-9 base slot. */
        ".globl _sys_open\n"
        "_sys_open:\n"
        "  mov eax, 5\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_dlsym(int handle, const char* name, void** dest)  -- 591
           sys_dynlib_dlsym / getFunctionAddressByName (SDK module.c);
           console-proven on this FW: the HEN installer resolves its whole
           libc/kernel through it (initKernel/initLibc RESOLVE lists). */
        ".globl _sys_dlsym\n"
        "_sys_dlsym:\n"
        "  mov eax, 591\n"
        "  mov r10, rcx\n"
        "  syscall\n"
        "  jb 9f\n"
        "  ret\n"

        /* int _sys_getlist(int* ids, int max, int* count)  -- 592
           sys_dynlib_get_list / getLoadedModules(destination, max, count)
           (SDK module.h): lists the ALREADY-LOADED module handles of this
           process. Read-only enumeration -- nothing is loaded. */
        ".globl _sys_getlist\n"
        "_sys_getlist:\n"
        "  mov eax, 592\n"
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
extern int  _sys_connect(int fd, const void *addr, int addrlen);
extern long _sys_write(int fd, const void *buf, u64 len);
extern int  _sys_open(const char *path, int flags, int mode);
extern int  _sys_dlsym(int handle, const char *name, void **dest);
extern int  _sys_getlist(int *ids, int max, int *count);

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

/* beacon/notify marker: 8-byte magic + 26 bytes "ip:port" (NUL-padded).
   afterglow-g.js rewrites the 26 bytes with the serving host at fetch time;
   the stub uses the value for its own beacons AND patches it into every
   received payload (the HEN installer carries the same marker) so installer
   beacons reach the server on the nc path too. Exactly ONE "BCNIP001"
   sequence exists in this blob (verify scripts check that). */
static const char beacon_cfg[34] = "BCNIP001" "192.168.100.123:8000";

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

#define O_WRONLY       1
#define FNONBLOCK      0x4            /* FreeBSD FNONBLOCK == O_NONBLOCK */

/* ---- on-screen notify popup (raw /dev/notification0 write, zero libkernel
   interaction) ---- */

/* SceNotificationRequest, size 0xC30, field-for-field from the researched
   layout (OSM-Made/PS4-Notify == libPS4 kernel.h): Message type = 0,
   target_id = -1, has_icon = 1 at 0x2C, message[0x400] at 0x2D,
   icon_image_uri[0x800] at 0x42D. The kernel forwards /dev/notification0/1
   writes to SceShellUI, which renders the popup. */
struct nreq {
  int  type;                /* 0x00: SceNotificationRequestType::Message = 0 */
  int  req_id;              /* 0x04 */
  int  priority;            /* 0x08 */
  int  msg_id;              /* 0x0C */
  int  target_id;           /* 0x10 */
  int  user_id;             /* 0x14 */
  int  device_id;           /* 0x18 */
  int  addressing_user_id;  /* 0x1C */
  int  app_id;              /* 0x20 */
  int  error_num;           /* 0x24 */
  int  attribute;           /* 0x28 */
  char use_icon_image_uri;  /* 0x2C */
  char message[1024];       /* 0x2D  (0x400) */
  char uri[2048];           /* 0x42D (0x800) */
  char tail[3];             /* pad -> 0xC30 */
};

/* the researched layout is asserted, never assumed */
_Static_assert(sizeof(struct nreq) == 0xC30, "SceNotificationRequest must be 0xC30");

static int (*notify_fn)(int device, struct nreq *req, u64 size, int blocking);
static int notify_tried_dlsym;

static void beacon(const char *msg);
static void beacon_u(const char *msg, u32 val);

/* attempt one device write; returns 0 on success, else the failing step's rc */
static int notify_dev(const char *path, int flags, const struct nreq *req) {
  int fd = _sys_open(path, flags, 0);
  if (fd < 0) return fd;
  long w = _sys_write(fd, req, sizeof(*req));
  _sys_close(fd);
  return (int)w;
}

/* fallback: dlsym by ENUMERATION ONLY (getlist 592 -> dlsym 591 per handle).
   No module is ever loaded -- these are the process's own loaded modules. */
static void notify_dlsym_fallback(const struct nreq *req) {
  if (notify_tried_dlsym && !notify_fn) return;
  if (!notify_fn) {
    notify_tried_dlsym = 1;
    int ids[64];
    int n = 0;
    int rc = _sys_getlist(ids, 64, &n);
    if (rc != 0) { beacon_u("n1 gl rc", (u32)(-rc)); return; }
    if (n <= 0 || n > 64) { beacon_u("n1 gl n", (u32)n); return; }
    static const char sym[] = "sceKernelSendNotificationRequest";
    for (int i = 0; i < n; i++) {
      if (ids[i] <= 0) continue;
      void *fn = 0;
      if (_sys_dlsym(ids[i], sym, &fn) == 0 && fn) { notify_fn = (int (*)(int, struct nreq *, u64, int))fn; break; }
    }
    if (!notify_fn) { beacon("n1 sym not found"); return; }
    beacon_u("n1 h", (u32)(long)notify_fn);
  }
  int rc = notify_fn(0, (struct nreq *)req, sizeof(*req), 0);
  beacon_u("n1 rc", (u32)(rc < 0 ? -rc : rc));
}

static void notify(const char *msg) {
  struct nreq req;
  memset(&req, 0, sizeof(req));
  req.target_id = -1;                   /* researched: TargetId = -1 */
  req.use_icon_image_uri = 1;           /* HasIcon = 1 */
  req.type = 0;                         /* SceNotificationRequestType::Message */
  const char *icon = "cxml://psnotification/tex_icon_system";
  for (u32 i = 0; i < 2047 && icon[i]; i++) req.uri[i] = icon[i];
  for (u32 i = 0; i < 1023 && msg[i]; i++) req.message[i] = msg[i];

  /* primary: raw device writes, zero libkernel interaction */
  int rc = notify_dev("/dev/notification0", O_WRONLY | FNONBLOCK, &req);
  if (rc < 0) {
    beacon_u("n0 open rc", (u32)(-rc));
    int rc2 = notify_dev("/dev/notification0", O_WRONLY, &req);
    if (rc2 < 0) {
      beacon_u("n0 open2 rc", (u32)(-rc2));
      int rc3 = notify_dev("/dev/notification1", O_WRONLY | FNONBLOCK, &req);
      if (rc3 < 0) {
        beacon_u("n1 open rc", (u32)(-rc3));
        notify_dlsym_fallback(&req);   /* last resort, enumeration only */
        return;
      }
      beacon("n1 w ok");
      return;
    }
    beacon("n0 w ok");
    return;
  }
  beacon("n0 w ok");
}

/* ---- stage beacons: one TCP GET to the server's /hb route per event ---- */

/* parse beacon_cfg +8: "a.b.c.d:port" into a sockaddr, byte-explicit */
static struct sa_in beacon_sa;
static int beacon_ready;

static void beacon_parse(void) {
  beacon_sa.len = 16;
  beacon_sa.family = AF_INET;
  beacon_sa.port_be = 0;
  beacon_sa.addr = 0;
  for (int i = 0; i < 8; i++) beacon_sa.zero[i] = 0;

  const char *p = beacon_cfg + 8; /* skip the magic */
  u8 b[4];
  int n = 0;
  while (*p && n < 4) {
    u32 v = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (u32)(*p - '0'); p++; digits++; }
    if (!digits || v > 255) return;
    b[n++] = (u8)v;
    if (*p == '.') { p++; } else { break; }
  }
  if (n != 4 || *p != ':') return;
  p++;
  u32 port = 0;
  while (*p >= '0' && *p <= '9') {
    port = port * 10 + (u32)(*p - '0');
    p++;
    if (port > 65535) return;
  }
  if (!port || *p) return;

  beacon_sa.addr = ((u32)b[0]) | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
  beacon_sa.port_be = (u16)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
  beacon_ready = 1;
}

/* URL-encode one char into o (needs <=3 bytes); returns bytes written */
static u32 enc1(char *o, char c) {
  static const char hex[] = "0123456789ABCDEF";
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
      c == '-' || c == '.' || c == '_' || c == '~') { o[0] = c; return 1; }
  o[0] = '%';
  o[1] = hex[((u8)c >> 4) & 15];
  o[2] = hex[(u8)c & 15];
  return 3;
}

static u32 emit_udec(char *o, u32 v) {
  char t[12];
  u32 n = 0;
  do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  u32 w = 0;
  while (n) { o[w++] = t[--n]; }
  return w;
}

static void beacon_send(const char *msg) {
  if (!beacon_ready) beacon_parse();
  if (!beacon_ready) return;

  char req[640];
  u32 o = 0;
  const char *pre = "GET /hb?m=";
  while (*pre) req[o++] = *pre++;
  const char *tag = "[bld] ";
  while (*tag) o += enc1(req + o, *tag++);
  for (u32 i = 0; msg[i] && i < 160; i++) o += enc1(req + o, msg[i]);
  const char *post = " HTTP/1.0\r\n\r\n";
  while (*post) req[o++] = *post++;

  int s = _sys_socket(AF_INET, SOCK_STREAM, 0);
  if (s <= 0) return;
  if (_sys_connect(s, &beacon_sa, (int)sizeof(beacon_sa)) != 0) { _sys_close(s); return; }
  _sys_write(s, req, o);
  _sys_close(s);
}

static void beacon(const char *msg) { beacon_send(msg); }

static void beacon_u(const char *msg, u32 val) {
  char buf[192];
  u32 o = 0;
  for (u32 i = 0; msg[i] && o < 128; i++) buf[o++] = msg[i];
  if (o < sizeof(buf) - 1) buf[o++] = ' ';
  if (o < sizeof(buf) - 12) o += emit_udec(buf + o, val);
  buf[o] = 0;
  beacon_send(buf);
}

static void byte_copy(u64 dst, u64 src, u64 n) {
  u8 *d = (u8 *)dst; const u8 *s = (const u8 *)src;
  while (n) { *d++ = *s++; n--; }
}

/* ---- ELF64 payload support (v4) ----
   All header reads are byte-explicit little-endian (rd16/rd32/rd64): no
   struct definitions, so no alignment/padding assumptions can drift. */

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define ET_EXEC    2
#define ET_DYN     3
#define EM_X86_64  62
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define DT_RELA    7
#define DT_RELASZ  8
#define DT_RELAENT 9
#define R_X86_64_RELATIVE 8
#define ELF_PHDR_MAX     16u
#define ELF_SPAN_MAX     (64u * 1024u * 1024u)
#define ELF_RELA_MAX     (1u * 1024u * 1024u)
#define ELF_PHENT_MIN    56u

static u64 rd16(const u8 *p) { return (u64)p[0] | ((u64)p[1] << 8); }
static u64 rd32(const u8 *p) { return (u64)p[0] | ((u64)p[1] << 8) | ((u64)p[2] << 16) | ((u64)p[3] << 24); }
static u64 rd64(const u8 *p) { return rd32(p) | (rd32(p + 4) << 32); }

/* Load one received ELF64 image and run it. Returns 0 after the payload
   returned; <0 = refusal (reason beaconed, caller re-listens). */
static int elf_exec(u8 *blob, u64 total) {
  if (total < 64) { beacon("x! hdr short"); return -1; }
  if (blob[4] != ELFCLASS64 || blob[5] != ELFDATA2LSB) { beacon("x! not elf64"); return -2; }

  u64 e_type    = rd16(blob + 16);
  u64 e_machine = rd16(blob + 18);
  u64 e_entry   = rd64(blob + 24);
  u64 e_phoff   = rd64(blob + 32);
  u64 e_phent   = rd16(blob + 54);
  u64 e_phnum   = rd16(blob + 56);
  if (!(e_type == ET_EXEC || e_type == ET_DYN) || e_machine != EM_X86_64) {
    beacon_u("x! type/mach", (u32)((e_type << 16) | e_machine)); return -3;
  }
  if (e_phoff == 0 || e_phnum == 0 || e_phnum > ELF_PHDR_MAX || e_phent < ELF_PHENT_MIN) {
    beacon("x! phdr hdr"); return -4;
  }
  if (e_phoff + e_phnum * e_phent > total) { beacon("x! phdr oob"); return -5; }
  beacon_u("e1 phnum", (u32)e_phnum);

  /* pass 1: validate every segment, find PT_DYNAMIC, compute the span */
  u64 min_vaddr = 0, max_end = 0;
  int loads = 0, dyn_idx = -1;
  for (u64 i = 0; i < e_phnum; i++) {
    const u8 *ph = blob + e_phoff + i * e_phent;
    u64 p_type   = rd32(ph);
    u64 p_offset = rd64(ph + 8);
    u64 p_vaddr  = rd64(ph + 16);
    u64 p_filesz = rd64(ph + 32);
    u64 p_memsz  = rd64(ph + 40);
    if (p_type == PT_INTERP) { beacon("x! interp"); return -6; }
    if (p_type != PT_LOAD && p_type != PT_DYNAMIC) continue;
    if (p_offset + p_filesz > total) { beacon_u("x! seg oob", (u32)i); return -7; }
    if (p_type == PT_DYNAMIC && dyn_idx < 0) dyn_idx = (int)i;
    if (p_type == PT_LOAD && p_memsz) {
      if (!loads || p_vaddr < min_vaddr) min_vaddr = p_vaddr;
      if (!loads || p_vaddr + p_memsz > max_end) max_end = p_vaddr + p_memsz;
      loads++;
    }
  }
  beacon_u("e2 loads", (u32)loads);
  if (loads == 0 || max_end <= min_vaddr) { beacon("x! no load"); return -8; }

  u64 span = max_end - min_vaddr;
  if (span > ELF_SPAN_MAX) { beacon_u("x! span", (u32)(span >> 20)); return -9; }
  beacon_u("e3 span", (u32)span);

  u64 esz = (span + TAIL_PAD + 0x3FFFu) & ~(u64)0x3FFFu;
  u64 ex = _sys_mmap(0, esz, PROT_RW, MAP_ANON_PRIVATE, -1, 0);
  if ((s64)ex < 0) { beacon_u("x! map fail", (u32)(-ex)); return -10; }

  /* pass 2: zero each segment then copy its file bytes (bss handled by the
     memsz-vs-filesz difference; zero-first makes overlapped/odd layouts safe) */
  for (u64 i = 0; i < e_phnum; i++) {
    const u8 *ph = blob + e_phoff + i * e_phent;
    if (rd32(ph) != PT_LOAD) continue;
    u64 p_offset = rd64(ph + 8);
    u64 p_vaddr  = rd64(ph + 16);
    u64 p_filesz = rd64(ph + 32);
    u64 p_memsz  = rd64(ph + 40);
    u8 *dst = (u8 *)(ex + (p_vaddr - min_vaddr));
    memset(dst, 0, p_memsz);
    byte_copy((u64)dst, (u64)(blob + p_offset), p_filesz);
  }
  if (_sys_mprotect(ex, esz, PROT_RWX) != 0) { _sys_munmap(ex, esz); beacon("x! mprot fail"); return -11; }
  beacon("e4 loaded");

  /* relocations: only what a PIE payload legitimately carries
     (R_X86_64_RELATIVE). SDK-built ELFs have none (measured); OpenOrbis-
     style PIE ELFs have these. Anything else = honest refusal. */
  u64 rela_vaddr = 0, rela_sz = 0, rela_ent = 0;
  if (dyn_idx >= 0) {
    const u8 *ph = blob + e_phoff + (u64)dyn_idx * e_phent;
    u64 d_offset = rd64(ph + 8);
    u64 d_filesz = rd64(ph + 32);
    for (u64 o = 0; o + 16 <= d_filesz; o += 16) {
      u64 tag = rd64(blob + d_offset + o);
      u64 val = rd64(blob + d_offset + o + 8);
      if (tag == DT_RELA) rela_vaddr = val;
      else if (tag == DT_RELASZ) rela_sz = val;
      else if (tag == DT_RELAENT) rela_ent = val;
    }
  }
  if (rela_vaddr && rela_sz) {
    if (rela_ent != 24 || rela_sz > ELF_RELA_MAX || (rela_sz % 24) != 0) {
      beacon_u("x! rela hdr", (u32)rela_sz); _sys_munmap(ex, esz); return -12;
    }
    s64 rela_file = -1;
    for (u64 i = 0; i < e_phnum && rela_file < 0; i++) {
      const u8 *ph = blob + e_phoff + i * e_phent;
      if (rd32(ph) != PT_LOAD) continue;
      u64 p_offset = rd64(ph + 8);
      u64 p_vaddr  = rd64(ph + 16);
      u64 p_filesz = rd64(ph + 32);
      if (rela_vaddr >= p_vaddr && rela_vaddr + rela_sz <= p_vaddr + p_filesz)
        rela_file = (s64)(p_offset + (rela_vaddr - p_vaddr));
    }
    if (rela_file < 0 || (u64)rela_file + rela_sz > total) {
      beacon("x! rela oob"); _sys_munmap(ex, esz); return -13;
    }
    u32 nrel = 0;
    for (u64 o = 0; o < rela_sz; o += 24) {
      const u8 *r = blob + (u64)rela_file + o;
      u64 r_offset = rd64(r);
      u64 r_info   = rd64(r + 8);
      u64 r_addend = rd64(r + 16);
      if ((r_info & 0xFFFFFFFFull) != R_X86_64_RELATIVE) {
        beacon_u("x! reloc type", (u32)(r_info & 0xFFFFFFFFull));
        _sys_munmap(ex, esz); return -14;
      }
      if (r_offset < min_vaddr || r_offset + 8 > max_end ||
          r_addend < min_vaddr || r_addend >= max_end) {
        beacon_u("x! reloc dst", (u32)r_offset);
        _sys_munmap(ex, esz); return -15;
      }
      *(u64 *)(ex + (r_offset - min_vaddr)) = ex + (r_addend - min_vaddr);
      nrel++;
    }
    beacon_u("e5 rel", nrel);
  } else {
    beacon("e5 norel");
  }

  if (e_entry < min_vaddr || e_entry >= max_end) {
    beacon_u("x! entry oob", (u32)e_entry); _sys_munmap(ex, esz); return -16;
  }
  void *(*entry)(void *) = (void *(*)(void *))(ex + (e_entry - min_vaddr));
  beacon_u("e6 entry", (u32)(e_entry - min_vaddr));
  beacon("3 executing");
  entry((void *)0);
  _sys_munmap(ex, esz);
  return 0;
}

int _main(void *args) {
  (void)args;

  /* staging buffer, RW only, mapped once for the thread's lifetime */
  u64 stage = _sys_mmap(0, STAGE_MAX, PROT_RW, MAP_ANON_PRIVATE, -1, 0);
  if ((s64)stage < 0) return -1;

  int listen_announced = 0;

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

    if (!listen_announced) {
      listen_announced = 1;
      /* GoldHEN-style on-screen popup (no dashes in the text, user request)
         + a beacon line on the PC. No libkernel interaction anywhere. */
      notify("binloader listening on port 9020");
      beacon("1 listening on 9020");
    }

    int cfd = _sys_accept(sfd, 0, 0);
    if (cfd < 0) { _sys_close(sfd); continue; }

    /* receive until the sender closes (nc -q0 / --send-only / injectors) */
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

    /* validate: 0xE9 = raw payload (the convention this whole chain uses,
       hen-1402.bin included) OR 7F 45 4C 46 = ELF64 (scene-standard binloader
       payloads). Anything else: one honest beacon, then re-listen. Empty
       probe connections (total < MIN_PAYLOAD) stay silent. */
    const u8 *b0 = (const u8 *)stage;
    int is_raw = (b0[0] == 0xE9);
    int is_elf = (b0[0] == 0x7F && b0[1] == 0x45 && b0[2] == 0x4C && b0[3] == 0x46);
    if (total < MIN_PAYLOAD || (!is_raw && !is_elf)) {
      if (total >= MIN_PAYLOAD) beacon("x unknown format");
      continue;  /* re-listen */
    }

    /* patch the received payload's BCNIP001 marker (HEN installer carries one)
       with this stub's beacon host so installer beacons reach the server too.
       Works for both formats: the scan runs on the received bytes before they
       are copied into the exec image. */
    for (u64 i = 0; i + 34 <= total; i++) {
      if (((u8 *)stage)[i] == 'B' && ((u8 *)stage)[i+1] == 'C' &&
          ((u8 *)stage)[i+2] == 'N' && ((u8 *)stage)[i+3] == 'I' &&
          ((u8 *)stage)[i+4] == 'P' && ((u8 *)stage)[i+5] == '0' &&
          ((u8 *)stage)[i+6] == '0' && ((u8 *)stage)[i+7] == '1') {
        memcpy((void *)(stage + i + 8), beacon_cfg + 8, 26);
        break;
      }
    }

    notify("binloader executing payload");
    beacon_u("2 payload received", (u32)total);

    if (is_raw) {
      /* RAW path: byte-behavior identical to v3. Exec image = payload bytes
         + zero tail (GOT slots live there), page-rounded the same way the
         host loader rounds (size & ~0x3fff). */
      u64 esz = (total + TAIL_PAD + 0x3FFFu) & ~(u64)0x3FFFu;
      u64 ex  = _sys_mmap(0, esz, PROT_RW, MAP_ANON_PRIVATE, -1, 0);
      if ((s64)ex < 0) continue;

      byte_copy(ex, stage, total);
      if (_sys_mprotect(ex, esz, PROT_RWX) != 0) { _sys_munmap(ex, esz); continue; }

      /* same call convention as the host loader: pthread_create(fn=entry, arg=0).
         Runs synchronously on THIS thread; when the payload returns, we serve the
         next one. */
      void *(*entry)(void *) = (void *(*)(void *))ex;
      beacon("3 executing");
      entry((void *)0);

      _sys_munmap(ex, esz);
    } else {
      /* ELF64 path: refusal codes are beaconed inside elf_exec. */
      elf_exec((u8 *)stage, total);
    }
    /* loop: accept the next payload */
  }

  /* not reached */
  _sys_munmap(stage, STAGE_MAX);
  return 0;
}
