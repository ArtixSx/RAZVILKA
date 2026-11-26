/* Lab-only fault tests for the separately pinned MIT-licensed HEV source.
 * The detector source itself is included unchanged after applying our patch;
 * only its allocation/OS calls are replaced. No production binary is replaced.
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned long kernel_min;
static long recommended;
static int operation, fail_first, fail_second, malloc_fail, allocations, frees;
static void *allocation;
static size_t allocation_size;
static int abort_notice = -1;
static stack_t current_stack, original_stack;
static struct sigaction current_bus, current_segv, original_bus, original_segv;

static void old_bus (int value) { (void)value; }
static void old_segv (int value) { (void)value; }

static int fault (void)
{
    operation++;
    if (operation == fail_first || operation == fail_second) {
        errno = EIO;
        return 1;
    }
    return 0;
}

static unsigned long test_getauxval (unsigned long type)
{
    assert (type == AT_MINSIGSTKSZ);
    return kernel_min;
}
static long test_sysconf (int type)
{
    assert (type == _SC_SIGSTKSZ);
    return recommended;
}
static void *test_malloc (size_t size)
{
    allocations++;
    if (malloc_fail) {
        errno = ENOMEM;
        return NULL;
    }
    assert (!allocation);
    allocation_size = size;
    allocation = malloc (size);
    assert (allocation);
    return allocation;
}
static void test_free (void *ptr)
{
    uintptr_t low = (uintptr_t)allocation;
    uintptr_t active = (uintptr_t)current_stack.ss_sp;
    assert (ptr == allocation);
    assert (active < low || active >= low + allocation_size);
    assert (current_bus.sa_handler == original_bus.sa_handler);
    assert (current_segv.sa_handler == original_segv.sa_handler);
    frees++;
    free (ptr);
    allocation = NULL;
}
static int test_sigaltstack (const stack_t *ss, stack_t *old)
{
    if (fault ())
        return -1;
    if (ss && !(ss->ss_flags & SS_DISABLE) && ss->ss_size < kernel_min) {
        errno = ENOMEM;
        return -1;
    }
    if (old)
        *old = current_stack;
    if (ss)
        current_stack = *ss;
    return 0;
}
static int test_sigaction (int number, const struct sigaction *action,
                          struct sigaction *old)
{
    struct sigaction *current;
    assert (number == SIGBUS || number == SIGSEGV);
    if (fault ())
        return -1;
    current = number == SIGBUS ? &current_bus : &current_segv;
    if (old)
        *old = *current;
    if (action)
        *current = *action;
    return 0;
}
static _Noreturn void test_abort (void)
{
    const char marker = 'A';
    /* Only the detector's explicit fail-closed abort emits this marker.
     * An assertion/UAF-triggered SIGABRT must not satisfy expect_abort. */
    assert (allocation && allocations == 1 && frees == 0 && abort_notice >= 0);
    assert (write (abort_notice, &marker, 1) == 1);
    abort ();
}

#define malloc(size) test_malloc(size)
#define free(ptr) test_free(ptr)
#define sigaltstack(ss, old) test_sigaltstack(ss, old)
#define sigaction(number, action, old) test_sigaction(number, action, old)
#define getauxval(type) test_getauxval(type)
#define sysconf(type) test_sysconf(type)
#define abort() test_abort()
#include HEV_STACK_SOURCE
#undef malloc
#undef free
#undef sigaltstack
#undef sigaction
#undef getauxval
#undef sysconf
#undef abort

static void reset (unsigned long minimum, long suggested)
{
    assert (!allocation);
    operation = fail_first = fail_second = malloc_fail = allocations = frees = 0;
    kernel_min = minimum;
    recommended = suggested;
    memset (&original_stack, 0, sizeof (original_stack));
    original_stack.ss_sp = (void *)(uintptr_t)0x12340;
    original_stack.ss_size = 65536;
    memset (&original_bus, 0, sizeof (original_bus));
    memset (&original_segv, 0, sizeof (original_segv));
    original_bus.sa_handler = old_bus;
    original_segv.sa_handler = old_segv;
    current_stack = original_stack;
    current_bus = original_bus;
    current_segv = original_segv;
}
static void restored (void)
{
    assert (!allocation && frees == 1);
    assert (current_stack.ss_sp == original_stack.ss_sp);
    assert (current_stack.ss_size == original_stack.ss_size);
    assert (current_bus.sa_handler == original_bus.sa_handler);
    assert (current_segv.sa_handler == original_segv.sa_handler);
}
static void expect_abort (int first, int second, int destroy)
{
    int notice[2];
    assert (pipe (notice) == 0);
    pid_t pid = fork ();
    int status;
    assert (pid >= 0);
    if (!pid) {
        HevTaskStackDetector *detector;
        close (notice[0]);
        abort_notice = notice[1];
        reset (11952, 19120);
        if (destroy) {
            detector = hev_task_stack_detector_new ();
            assert (detector);
            operation = 0;
            fail_first = first;
            hev_task_stack_detector_destroy (detector);
        } else {
            fail_first = first;
            fail_second = second;
            (void)hev_task_stack_detector_new ();
        }
        _exit (99);
    }
    close (notice[1]);
    assert (waitpid (pid, &status, 0) == pid);
    char marker = 0, extra = 0;
    assert (read (notice[0], &marker, 1) == 1 && marker == 'A');
    assert (read (notice[0], &extra, 1) == 0);
    close (notice[0]);
    assert (WIFSIGNALED (status) && WTERMSIG (status) == SIGABRT);
}
int main (void)
{
    HevTaskStackDetector *detector;
    const unsigned long minima[] = {0, 3632, 11952};
    for (size_t i = 0; i < sizeof (minima) / sizeof (minima[0]); i++) {
        reset (minima[i], -1);
        detector = hev_task_stack_detector_new ();
        assert (detector && current_stack.ss_size == minima[i] + SIGSTKSZ);
        assert (allocation_size == sizeof (*detector) + current_stack.ss_size);
        assert (current_bus.sa_flags & SA_ONSTACK);
        assert (current_segv.sa_flags & SA_ONSTACK);
        hev_task_stack_detector_destroy (detector);
        restored ();
    }
    reset (11952, 65536);
    detector = hev_task_stack_detector_new ();
    assert (detector && current_stack.ss_size == 65536);
    hev_task_stack_detector_destroy (detector);
    restored ();
    reset (ULONG_MAX, -1);
    assert (!hev_task_stack_detector_new () && errno == ENOMEM && !allocations);
    reset (SIZE_MAX - SIGSTKSZ, -1);
    assert (!hev_task_stack_detector_new () && errno == ENOMEM && !allocations);
    reset (11952, 19120);
    malloc_fail = 1;
    assert (!hev_task_stack_detector_new () && errno == ENOMEM && allocations == 1 && !frees);
    for (int step = 1; step <= 3; step++) {
        reset (11952, 19120);
        fail_first = step;
        assert (!hev_task_stack_detector_new () && errno == EIO);
        restored ();
    }
    expect_abort (2, 3, 0); /* SIGBUS install + stack restoration refusal. */
    expect_abort (3, 4, 0); /* SIGSEGV install + old SIGBUS restoration refusal. */
    expect_abort (3, 5, 0); /* SIGSEGV install + old stack restoration refusal. */
    for (int step = 1; step <= 3; step++)
        expect_abort (step, 0, 1);
    puts ("HEV_RUNTIME_ALTSTACK_FAULT_CONTRACT_PASS");
    return 0;
}
