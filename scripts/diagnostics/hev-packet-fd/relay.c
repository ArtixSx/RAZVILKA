/* SPDX-License-Identifier: MIT
 * Lab process. It owns both ends of an exclusive, ephemeral TUN/HEV bridge.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "hev-main.h"

enum { MTU = 1500 };
struct packet { unsigned char data[MTU + 1]; size_t length; };
static volatile sig_atomic_t stopping;

static void stop(int signo) { (void)signo; stopping = 1; }
static int transient(void) { return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK; }

static int receive_packet(int fd, int is_unix_socket, struct packet *pkt)
{
    ssize_t n;
    if (is_unix_socket) {
        /* With MSG_TRUNC, n is the full datagram length even on truncation. */
        n = recv(fd, pkt->data, sizeof(pkt->data), MSG_DONTWAIT | MSG_TRUNC);
    } else {
        n = read(fd, pkt->data, sizeof(pkt->data));
    }
    if (n < 0 && transient()) return 0;
    /* lwIP also emits IPv6 control traffic. This fixture enrolls IPv4 only. */
    if (n >= 40 && n <= MTU && (pkt->data[0] >> 4) == 6 &&
        ((pkt->data[4] << 8) | pkt->data[5]) + 40 == n) return 0;
    if (n < 20 || n > MTU || (pkt->data[0] >> 4) != 4 ||
        (pkt->data[0] & 15) < 5 || (pkt->data[0] & 15) * 4 > n ||
        ((pkt->data[2] << 8) | pkt->data[3]) != n) {
        fprintf(stderr, "invalid IPv4 packet size=%zd version=%d direction=%s\n", n, n > 0 ? pkt->data[0] >> 4 : -1, is_unix_socket ? "reply" : "request");
        return -1;
    }
    pkt->length = (size_t)n;
    return 0;
}

static int send_packet(int fd, int is_unix_socket, struct packet *pkt, unsigned long *count)
{
    ssize_t n = is_unix_socket ? send(fd, pkt->data, pkt->length, MSG_DONTWAIT | MSG_NOSIGNAL)
                               : write(fd, pkt->data, pkt->length);
    if (n < 0 && transient()) return 0;
    if (n < 0 || (size_t)n != pkt->length) return -1;
    ++*count;
    pkt->length = 0;
    return 0;
}

int main(int argc, char **argv)
{
    struct ifreq ifr = { .ifr_name = "rzfd0", .ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL };
    int channel[2], status, result = 1;
    unsigned long outgoing = 0, returning = 0;
    struct packet outbound = {0}, inbound = {0};
    if (argc != 2 && argc != 3) return 2;
    const int queued=(argc==3);
    int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (tun < 0 || ioctl(tun, TUNSETIFF, &ifr) < 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, channel)) {
        perror("TUN/socketpair creation"); return 1;
    }
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(tun); close(channel[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent) _exit(1);
        int rc = hev_socks5_tunnel_main_from_file(argv[1], channel[1]);
        close(channel[1]); _exit(rc ? 1 : 0);
    }
    close(channel[1]);
    pid_t source = 0;
    if (queued) {
        source=fork();
        if (source < 0) goto done;
        if (source==0) {
            close(tun);
            if (dup2(channel[0],3)<0 || prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent) _exit(1);
            if (channel[0]!=3) close(channel[0]);
            execl(argv[2],argv[2],(char*)NULL);
            _exit(1);
        }
    }
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) goto done;
    while (!stopping) {
        pid_t ended = waitpid(child, &status, WNOHANG);
        if (ended == child) { child = 0; break; }
        if (ended < 0 && errno != EINTR) break;
        if (source>0) {
            pid_t finished=waitpid(source,&status,WNOHANG);
            if (finished==source) {source=0; break;}
            if (finished<0 && errno!=EINTR) break;
        }
        struct pollfd fds[] = {
            { .fd=tun, .events = ((queued || outbound.length) ? 0 : POLLIN) | (inbound.length ? POLLOUT : 0) },
            { .fd=channel[0], .events = (inbound.length ? 0 : POLLIN) | (outbound.length ? POLLOUT : 0) },
        };
        int ready = poll(fds, 2, 200);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL))) break;
        if ((fds[0].revents & POLLIN) && receive_packet(tun, 0, &outbound)) break;
        if ((fds[1].revents & POLLIN) && receive_packet(channel[0], 1, &inbound)) break;
        if ((fds[1].revents & POLLOUT) && send_packet(channel[0], 1, &outbound, &outgoing)) break;
        if ((fds[0].revents & POLLOUT) && send_packet(tun, 0, &inbound, &returning)) break;
    }
    result = stopping ? 0 : 1;
done:
    if (source>0) {
        if (kill(source,SIGTERM)<0 && errno!=ESRCH) result=1;
        pid_t ended;
        do { ended=waitpid(source,&status,0); } while(ended<0 && errno==EINTR);
        if (ended!=source || !WIFEXITED(status) || WEXITSTATUS(status)!=0) result=1;
    }
    if (child > 0) {
        if (kill(child, SIGTERM) < 0 && errno != ESRCH) result = 1;
        pid_t ended;
        do { ended = waitpid(child, &status, 0); } while (ended < 0 && errno == EINTR);
        if (ended != child) result = 1;
    }
    close(channel[0]); close(tun);
    printf("relay_packets_to_hev=%lu relay_packets_to_original_tun=%lu\n", outgoing, returning);
    return result;
}
