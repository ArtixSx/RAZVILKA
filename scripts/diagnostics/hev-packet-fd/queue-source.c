/* SPDX-License-Identifier: MIT
 * Optional isolated NFQUEUE packet source. The supervisor passes an already
 * connected HEV socket; every enrolled original gets a DROP verdict.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
enum { GROUP = 17747, HEV_FD = 3, MAX_PACKET = 1500 };
struct state { struct mnl_socket *nl; unsigned long packets; };
static volatile sig_atomic_t stopping;
static void stop(int signo) { (void)signo; stopping = 1; }

static int valid_ip_tcp(const unsigned char *p, size_t n)
{
    static const unsigned char home[] = {192,168,70};
    static const unsigned char target[] = {192,0,2,12};
    if (n < 40 || n > MAX_PACKET || (p[0] >> 4) != 4 || p[9] != IPPROTO_TCP ||
        ((unsigned)p[2] << 8 | p[3]) != n || (p[6] & 0x3f) || p[7] ||
        memcmp(p + 12, home, sizeof(home)) || (p[15] < 2 || p[15] == 255) ||
        memcmp(p + 16, target, sizeof(target))) return 0;
    size_t ihl=(p[0] & 15u) * 4;
    return ihl >= 20 && ihl+20 <= n && ((unsigned)p[ihl+2] << 8 | p[ihl+3]) == 443;
}

static int forward_packet(const struct nlmsghdr *nlh, void *opaque)
{
    struct state *st=opaque;
    struct nlattr *a[NFQA_MAX+1] = {0};
    if (nfq_nlmsg_parse(nlh,a) < 0 || !a[NFQA_PACKET_HDR]) return MNL_CB_ERROR;
    const struct nfqnl_msg_packet_hdr *hdr=mnl_attr_get_payload(a[NFQA_PACKET_HDR]);
    int delivered=0;
    if (a[NFQA_PAYLOAD] && ntohs(hdr->hw_protocol)==0x0800) {
        const unsigned char *p=mnl_attr_get_payload(a[NFQA_PAYLOAD]);
        size_t n=mnl_attr_get_payload_len(a[NFQA_PAYLOAD]);
        if ((!a[NFQA_CAP_LEN] || ntohl(mnl_attr_get_u32(a[NFQA_CAP_LEN]))==n) && valid_ip_tcp(p,n)) {
            struct pollfd peer={.fd=HEV_FD,.events=POLLOUT};
            if (poll(&peer,1,1000)>0 && (peer.revents & POLLOUT))
                delivered=send(HEV_FD,p,n,MSG_DONTWAIT|MSG_NOSIGNAL)==(ssize_t)n;
        }
    }
    char verdict[256];
    struct nlmsghdr *v=nfq_nlmsg_put(verdict,NFQNL_MSG_VERDICT,GROUP);
    nfq_nlmsg_verdict_put(v,ntohl(hdr->packet_id),NF_DROP);
    if (mnl_socket_sendto(st->nl,v,v->nlmsg_len)<0 || !delivered) return MNL_CB_ERROR;
    st->packets++;
    return MNL_CB_OK;
}

static int configure(struct state *st, unsigned int seq, unsigned int max_packets)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *msg=nfq_nlmsg_put(buf,NFQNL_MSG_CONFIG,GROUP);
    msg->nlmsg_flags|=NLM_F_ACK;
    msg->nlmsg_seq=seq;
    if (seq==1) nfq_nlmsg_cfg_put_cmd(msg,AF_INET,NFQNL_CFG_CMD_BIND);
    else {
        nfq_nlmsg_cfg_put_params(msg,NFQNL_COPY_PACKET,65535);
        nfq_nlmsg_cfg_put_qmaxlen(msg,max_packets);
        mnl_attr_put_u32(msg,NFQA_CFG_MASK,htonl(NFQA_CFG_F_GSO|NFQA_CFG_F_FAIL_OPEN));
        mnl_attr_put_u32(msg,NFQA_CFG_FLAGS,0);
    }
    if (mnl_socket_sendto(st->nl,msg,msg->nlmsg_len)<0) return -1;
    ssize_t n=mnl_socket_recvfrom(st->nl,buf,sizeof(buf));
    return n>=0 && mnl_cb_run(buf,n,seq,mnl_socket_get_portid(st->nl),NULL,NULL)==MNL_CB_STOP ? 0 : -1;
}
int main(int argc, char **argv)
{
    int hold_one = argc == 2 && strcmp(argv[1], "--hold-one") == 0;
    int type;
    socklen_t l = sizeof(type);
    struct stat outer, here;
    if (argc != 1 && !hold_one) return 2;
    if (fstat(8,&outer)||stat("/proc/self/ns/net",&here) ||
        (outer.st_dev==here.st_dev && outer.st_ino==here.st_ino)) return 2;
    if (!hold_one && (getsockopt(HEV_FD, SOL_SOCKET, SO_TYPE, &type, &l) || type != SOCK_DGRAM)) return 2;
    struct state st={.nl=mnl_socket_open(NETLINK_NETFILTER)};
    int result=1;
    if (!st.nl || mnl_socket_bind(st.nl,0,MNL_SOCKET_AUTOPID)<0 ||
        configure(&st,1,hold_one ? 1 : 512) || configure(&st,2,hold_one ? 1 : 512)) { perror("NFQUEUE setup"); return 1; }
    struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM,&action,NULL)) return 1;
    fprintf(stderr,"nfqueue-ready\n");
    char buf[131072];
    while (hold_one && !stopping) {
        poll(NULL, 0, 100);
    }
    while (!stopping) {
        struct pollfd fd={.fd=mnl_socket_get_fd(st.nl),.events=POLLIN};
        int ready=poll(&fd,1,200);
        if (ready<0 && errno==EINTR) continue;
        if (ready<0 || fd.revents & (POLLERR|POLLNVAL|POLLHUP)) break;
        if (!ready) continue;
        ssize_t n=mnl_socket_recvfrom(st.nl,buf,sizeof(buf));
        if (n<=0 || mnl_cb_run(buf,n,0,mnl_socket_get_portid(st.nl),forward_packet,&st)<0) break;
    }
    if (stopping) result=0;
    fprintf(stderr,"nfqueue-complete-packets=%lu\n",st.packets);
    mnl_socket_close(st.nl);
    return result;
}
