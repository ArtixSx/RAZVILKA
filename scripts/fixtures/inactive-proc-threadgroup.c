#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Private native fixture: pipes only, no sockets, routes or controller work. */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start = PTHREAD_COND_INITIALIZER;
static int released;
static char executable[PATH_MAX];
static char state_arg[PATH_MAX];

static void send_byte(char value) {
    ssize_t n;
    do { n = write(4, &value, 1); } while (n < 0 && errno == EINTR);
    if (n != 1) _exit(91);
}
static char receive_byte(void) {
    char value;
    ssize_t n;
    do { n = read(3, &value, 1); } while (n < 0 && errno == EINTR);
    if (n != 1) _exit(92);
    return value;
}
static void command_loop(char ready) {
    send_byte(ready);
    for (;;) {
        switch (receive_byte()) {
        case 'P': send_byte('P'); break;
        case 'Q': _exit(0);
        case 'X': {
            char *next[] = {"mihomo", "after-exec", executable, state_arg, NULL};
            execv(executable, next);
            _exit(93);
        }
        default: _exit(94);
        }
    }
}
static void *worker(void *unused) {
    (void)unused;
    if (pthread_mutex_lock(&lock) != 0) _exit(95);
    while (!released) if (pthread_cond_wait(&start, &lock) != 0) _exit(96);
    if (pthread_mutex_unlock(&lock) != 0) _exit(97);
    command_loop('W');
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 4 || argv[2][0] != '/' || strlen(argv[2]) >= sizeof(executable) ||
        strncmp(argv[3], "--dataplane-state=/", 18) != 0 || strlen(argv[3]) >= sizeof(state_arg)) return 90;
    strcpy(executable, argv[2]);
    strcpy(state_arg, argv[3]);
    if (strcmp(argv[1], "after-exec") == 0) command_loop('E');
    if (strcmp(argv[1], "single") == 0) command_loop('S');
    if (strcmp(argv[1], "leader") != 0) return 90;
    pthread_t child;
    if (pthread_create(&child, NULL, worker, NULL) != 0) return 98;
    send_byte('L');
    if (receive_byte() != 'Z') return 94;
    if (pthread_mutex_lock(&lock) != 0) return 95;
    released = 1;
    if (pthread_cond_signal(&start) != 0 || pthread_mutex_unlock(&lock) != 0) return 97;
    pthread_exit(NULL); /* Original leader dies; independently pinged worker lives. */
}
