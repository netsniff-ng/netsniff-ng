/* 
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009  Daniel Borkmann <danborkmann@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

#define PROGNAME_STRING "netsniff-ng"
#define VERSION_STRING  "0.5.3"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>  
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netsniff-ng.h>

typedef unsigned char *ring_buff_bytes_t;

typedef struct ring_buff_private {
    ring_buff_bytes_t    buffer;
    uint32               len;
    struct tpacket_req   layout;
    struct iovec        *frames;
    struct sockaddr_ll   params;
} ring_buff_t;

struct frame_map {
    struct tpacket_hdr  tp_h __attribute__((aligned(TPACKET_ALIGNMENT)));
    struct sockaddr_ll  s_ll __attribute__((aligned(TPACKET_ALIGNMENT)));
};

#ifndef NZERO
#define NZERO 20
#endif

#define likely(x)    __builtin_expect((x),1)
#define unlikely(x)  __builtin_expect((x),0)

#define INTERVAL 1000
#define INTERNAL_UDS_QUEUE_LEN  50

volatile sig_atomic_t sysdeamon_v = 0;

volatile sig_atomic_t sigint = 0;
volatile sig_atomic_t nice_last;

ring_buff_stat_t netstat;

pthread_mutex_t gs_loc_mutex;

#define dbg(fmt, arg...) \
        fprintf(stderr, "I: "); \
        fprintf(stderr, fmt, ## arg);

#define err(fmt, arg...) \
        fprintf(stderr, "E: "); \
        fprintf(stderr, fmt, ## arg); \
        fflush(stderr);

void help()
{
    printf("%s %s, <danborkmann@googlemail.com>\n\n", PROGNAME_STRING, VERSION_STRING);
    printf("%s is a high performance network sniffer for packet\n", PROGNAME_STRING);
    printf("inspection that acts as a raw socket sniffer with kernelspace\n");
    printf("bpf and zero copy mode (rx ring).\n");
    printf("\n");
    printf("Options, required:\n");
    printf("    -d <arg>    use device <arg> for capturing packets\n");
    printf("    -f <arg>    use file <arg> as bpf filter\n");
    printf("\n");
    printf("Options, optional:\n");
    printf("    -P <arg>    use file <arg> as pidfile, req if -D\n");
    printf("    -L <arg>    use file <arg> as logfile, req if -D\n");
    printf("    -S <arg>    use file <arg> as uds inode, req if -D\n");
    printf("    -D          run as sys daemon\n\n");
    printf("    -C          print captured packets\n");
    printf("    -v          prints out version\n");
    printf("    -h          prints out this help\n");
    printf("\n");
    printf("Info:\n");
    printf("    - Sending a SIGUSR1 will show current packet statistics\n");
    printf("    - Rule creation can be done with \'tcpdump -dd <rule>\',\n");
    printf("      see examples, or, of course manually by hand\n");
    printf("    - To access the running sys daemon you can use ipc via AF_UNIX\n");
    printf("    - For more help type \'man netsniff-ng\'\n");
    printf("\n");
    printf("Please report bugs to <danborkmann@googlemail.com>\n");
    printf("Copyright (C) 2009 Daniel Borkmann\n");
    printf("License: GNU GPL version 2\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n");

    exit(1);
}

void version()
{
    printf("%s %s, <danborkmann@googlemail.com>\n\n", PROGNAME_STRING, VERSION_STRING);
    printf("%s is a high performance network sniffer for packet\n", PROGNAME_STRING);
    printf("inspection that acts as a raw socket sniffer with kernelspace\n");
    printf("bpf and zero copy mode (rx ring).\n");
    printf("Please report bugs to <dborkman@fbimn.htwk-leipzig.de>\n");
    printf("Copyright (C) 2009 Daniel Borkmann\n");
    printf("License: GNU GPL version 2\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

inline uint64 timespec_micro_diff(struct timeval *a, struct timeval *b)
{
    return ((a->tv_sec * 1000000) + a->tv_usec) - 
           ((b->tv_sec * 1000000) + b->tv_usec);
}

inline uint64 timespec_sec_diff(struct timeval *a, struct timeval *b)
{
    return (a->tv_sec - b->tv_sec);
}

inline void ___refresh_counters()
{
#define CURR_WEIGHT 0.68f

    netstat.per_min.frames += netstat.per_sec.frames;
    netstat.per_min.bytes  += netstat.per_sec.bytes;
        
    netstat.t_elapsed++;
        
    if(unlikely(netstat.t_elapsed % 60 == 0)){
        netstat.s_per_min.frames = CURR_WEIGHT * netstat.per_min.frames + (1.f - CURR_WEIGHT) * netstat.s_per_min.frames;
        netstat.s_per_min.bytes  = CURR_WEIGHT * netstat.per_min.bytes  + (1.f - CURR_WEIGHT) * netstat.s_per_min.bytes;
            
        netstat.per_min.frames = netstat.per_min.bytes = 0;
    }

    netstat.s_per_sec.frames = CURR_WEIGHT * netstat.per_sec.frames + (1.f - CURR_WEIGHT) * netstat.s_per_sec.frames;
    netstat.s_per_sec.bytes  = CURR_WEIGHT * netstat.per_sec.bytes  + (1.f - CURR_WEIGHT) * netstat.s_per_sec.bytes;
        
    netstat.per_sec.frames = netstat.per_sec.bytes = 0;
}

inline void ___print_counters()
{
#define DIV_KBYTES(x) ((x) / (1024LLU))
#define DIV_MBYTES(x) ((x) / (1048576LLU))
#define DIV_GBYTES(x) ((x) / (1073741824LLU))
	
#define DIV_US2HOURS(x) ((x) / (3600000000LLU))
#define MOD_HOURS2US(x) ((x) % (3600000000LLU))
#define DIV_US2MINUT(x) ((x) / (60000000LLU))
#define MOD_MINUT2US(x) ((x) % (60000000LLU))
#define DIV_US2SECON(x) ((x) / (1000000LLU))
#define MOD_SECON2US(x) ((x) % (1000000LLU))
#define DIV_US2MILLI(x) ((x) / (1000LLU))
#define MOD_MILLI2US(x) ((x) % (1000LLU))

#define DIV_S2DAYS(x)  ((x) / (86400LLU))
#define MOD_DAYS2S(x)  ((x) % (86400LLU))
#define DIV_S2HOURS(x) ((x) / (3600LLU))
#define MOD_HOURS2S(x) ((x) % (3600LLU))
#define DIV_S2MINUT(x) ((x) / (60LLU))
#define MOD_MINUT2S(x) ((x) % (60LLU))

    uint64 diff;
    uint64 d_day, d_h, d_min, d_sec;
        
    struct timeval t_curr;

    gettimeofday(&t_curr, NULL);
    
    diff = timespec_sec_diff(&t_curr, &netstat.m_start);
        
    d_day = DIV_S2DAYS(diff);  diff = MOD_DAYS2S(diff);
    d_h   = DIV_S2HOURS(diff); diff = MOD_HOURS2S(diff);
    d_min = DIV_S2MINUT(diff); diff = MOD_MINUT2S(diff);
    d_sec = diff;

    dbg("stats summary:\n"); 
    dbg("--------------------------------------------------------------------------------------------\n");
    dbg("elapsed time: %llu d, %llu h, %llu min, %llu s\n", d_day, d_h, d_min, d_sec); 
    dbg("-----------+--------------------------+--------------------------+--------------------------\n");
    dbg("           |  per sec                 |  per min                 |  total                   \n");
    dbg("-----------+--------------------------+--------------------------+--------------------------\n");
    dbg("  frames   | %24llu | %24llu | %24llu \n", netstat.s_per_sec.frames, netstat.s_per_min.frames, netstat.total.frames);
    dbg("-----------+--------------------------+--------------------------+--------------------------\n");
    dbg("  in B     | %24llu | %24llu | %24llu \n", netstat.s_per_sec.bytes, netstat.s_per_min.bytes, netstat.total.bytes);
    dbg("  in KB    | %24llu | %24llu | %24llu \n", DIV_KBYTES(netstat.s_per_sec.bytes), DIV_KBYTES(netstat.s_per_min.bytes), DIV_KBYTES(netstat.total.bytes));
    dbg("  in MB    | %24llu | %24llu | %24llu \n", DIV_MBYTES(netstat.s_per_sec.bytes), DIV_MBYTES(netstat.s_per_min.bytes), DIV_MBYTES(netstat.total.bytes));
    dbg("  in GB    | %24llu | %24llu | %24llu \n", DIV_GBYTES(netstat.s_per_sec.bytes), DIV_GBYTES(netstat.s_per_min.bytes), DIV_GBYTES(netstat.total.bytes));
    dbg("-----------+--------------------------+--------------------------+--------------------------\n");
}

void softirq_hdl(int number)
{
    if(likely(number == SIGALRM)){
        ___refresh_counters();
    }else if(likely(number == SIGUSR1)){
        ___print_counters();
    }else if(likely(number == SIGINT)){
        sigint = 1;
        dbg("caught SIGINT! i\'ll quit\n");
    }
}

inline void hold_softirq_pthread()
{
    sigset_t block_mask;

    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    sigaddset(&block_mask, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &block_mask, NULL);
}

void *uds_thread(void *psock)
{
    int ret;
    int sock;
    
    /* signalmask is per thread. we don't want to interrupt the 
       send-syscall */
    hold_softirq_pthread();
    
    dbg("unix domain socket server: entering thread\n");
    sock = (int) psock;

    pthread_mutex_lock(&gs_loc_mutex);

    ret = send(sock, &netstat, sizeof(ring_buff_stat_t), 0);
    if(ret < 0){
        err("cannot send ring buffer stats - ");
        perror("");
    }

    pthread_mutex_unlock(&gs_loc_mutex);

    close(sock);

    dbg("unix domain socket server: quitting thread\n");
    pthread_exit(0);
}

void *start_uds_server(void *psockfile)
{
    int ret, len;
    int sock, sock2;

    char *sockfile = (char *) psockfile;

    pthread_t tid;

    struct sockaddr_un local;
    struct sockaddr_un remote;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sock < 0){
        err("cannot create uds socket %d - ", errno);
        perror("");
        pthread_exit(0);
    }

    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, sockfile, sizeof(local.sun_path));
    unlink(local.sun_path);

    len = strlen(local.sun_path) + sizeof(local.sun_family);

    dbg("bind socket to %s\n", local.sun_path);

    ret = bind(sock, (struct sockaddr *) &local, len);
    if(ret < 0){
        err("cannot bind uds socket %d - ", errno);
        perror("");
        pthread_exit(0);
    }

    ret = listen(sock, INTERNAL_UDS_QUEUE_LEN);
    if(ret < 0){
        err("cannot set up uds listening queue %d - ", errno);
        perror("");
        pthread_exit(0);
    }

    for(;;){
        int t = sizeof(remote);
        dbg("unix domain socket server: waiting for a connection\n");

        sock2 = accept(sock, (struct sockaddr *) &remote, (socklen_t *) &t);
        if(sock2 < 0){
            err("cannot do accept on uds socket %d - ", errno);
            perror("");
            pthread_exit(0);
        }

        dbg("unix domain socket server: connected to client\n");

        /* we're not interested in joining... so a single thread id is sufficient */
        ret = pthread_create(&tid, NULL, uds_thread, (void *) sock2);
        if(ret < 0){
            err("uds server: error creating thread - ");
            perror("");              
            pthread_exit(0);
        }
        
        pthread_detach(tid);
    }

    dbg("unix domain socket server: quit\n");
    pthread_exit(0);
}

int undaemonize(const char *pidfile)
{
    int ret;

    ret = unlink(pidfile);    
    if(ret < 0){
        err("cannot unlink pidfile - ");
        perror("");
        return ret;
    }

    return 0;
}

int daemonize(const char *pidfile, const char *logfile, const char *sockfile)
{
    int fd;
    int ret;
    
    char cpid[32];
    pid_t pid;
    
    pthread_t tid;
    pthread_attr_t attr;

    assert(pidfile != NULL && logfile != NULL);

    fd = open(pidfile, O_RDONLY);
    if(fd > 0){
        err("daemon already started. kill daemon and delete pid file %s\n", pidfile);
        close(fd);
        exit(1);
    }

    umask(022);

    pid = fork();
    if(pid < 0){
        err("fork: %d - ", pid);
        perror("");
        exit(1);
    }
    if(pid > 0){
        exit(0);
    }

    ret = setsid();
    if(ret < 0){
        err("setsid: %d - ", ret);
        perror("");
        exit(1);
    }

    pid = fork();
    if(pid < 0){
        err("fork: %d - ", pid);
        perror("");
        exit(1);
    }
    if(pid > 0){
        exit(0);
    }

    ret = chdir("/");
    if(ret < 0){
        err("chdir: %d - ", ret);
        perror("");
        exit(1);
    }

    snprintf(cpid, sizeof(cpid), "%d", getpid());

    fd = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0){
        err("open pidfile: %d - ", fd);
        perror("");
        exit(1);
    }

    write(fd, cpid, strlen(cpid));
    close(fd);

    fd = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0644);
    if(fd < 0){
        err("open logfile: %d - ", fd);
        perror("");
        exit(1);
    }

    if(fd != 2){
        dup2(fd, 2);
        close(fd);
    }

    fd = open("/dev/null", O_RDWR);
    if(fd < 0){
        err("open /dev/null: %d - ", fd);
        perror("");
        exit(1);
    }

    dup2(fd, 0);
    dup2(fd, 1);
    
    if(!logfile)
        dup2(fd, 2);

    if(fd > 2)
        close(fd);

    dbg("%s %s\n", PROGNAME_STRING, VERSION_STRING);
    dbg("daemon up and running\n");

    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

    ret = pthread_create(&tid, NULL, start_uds_server, (void *) sockfile);
    if(ret < 0){
        err("cannot create thread %d - ", errno);
        perror("");
        undaemonize(pidfile);            
        exit(1);
    }

    pthread_detach(tid);

    dbg("unix domain socket server up and running\n");

    return 0;
}

inline void change_nice(int new_val)
{
    if(new_val < 0 || new_val > 39)
        return;

    nice_last = nice(0) + NZERO;
    if(errno == -1){
        err("cannot fetch nice value\n");
        nice_last = NZERO;
        return;
    }
    
    nice(new_val - nice_last);
    if(errno == -1)
        err("cannot set nice value to %d\n", new_val);
}

inline void restore_nice()
{
    change_nice(nice_last);
}

inline void destroy_virt_ring(int sock, ring_buff_t *rb)
{
    assert(rb);

    memset(&(rb->layout), 0, sizeof(struct tpacket_req));
    setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *) &(rb->layout), sizeof(struct tpacket_req));

    if(rb->buffer){
        munmap(rb, rb->len);
        rb->buffer = 0;
        rb->len = 0;
    }
    
    free(rb->frames);
}

inline void create_virt_ring(int sock, ring_buff_t *rb)
{
    int ret;

    assert(rb);

    memset(&(rb->layout), 0, sizeof(struct tpacket_req));

    /* max: getpagesize() << 11  for i386 */
    rb->layout.tp_block_size = getpagesize() << 2; 
    rb->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;

    /* max: 15  for i386 */
    rb->layout.tp_block_nr = 1 << 13; 
    rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

__retry_sso:
    ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *) &(rb->layout), sizeof(struct tpacket_req));
    if(errno == ENOMEM && rb->layout.tp_block_nr > 1){
        rb->layout.tp_block_nr >>= 1;
        rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;
        goto __retry_sso;
    }
    if(ret < 0){
        err("setsockopt: creation of rx ring failed: %d - ", errno);
        perror("");
        close(sock);
        exit(1);
    }

    rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;
    
    dbg("%.2f MB allocated for rx ring: %d blocks, %d frames, %d frames per block, framesize: %d bytes, blocksize: %d bytes \n", 
        1. * rb->len / (1024 * 1024), rb->layout.tp_block_nr, rb->layout.tp_frame_nr,  
        rb->layout.tp_block_size / rb->layout.tp_frame_size, rb->layout.tp_frame_size, rb->layout.tp_block_size);
}

inline void mmap_virt_ring(int sock, ring_buff_t *rb)
{
    assert(rb);

    rb->buffer = mmap(0, rb->len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if(rb->buffer == MAP_FAILED){
        err("mmap: cannot mmap the rx ring: %d - ", errno);
        perror("");
        destroy_virt_ring(sock, rb);
        close(sock);
        exit(1);
    }
}

inline void bind_dev_to_ring(int sock, int ifindex, ring_buff_t *rb)
{
    int ret;

    assert(rb);

    memset(&(rb->params), 0, sizeof(struct sockaddr_ll));
    
    rb->params.sll_family = AF_PACKET;
    rb->params.sll_protocol = htons(ETH_P_ALL);
    rb->params.sll_ifindex = ifindex;
    rb->params.sll_hatype = 0;
    rb->params.sll_halen = 0;
    rb->params.sll_pkttype = 0;
    
    ret = bind(sock, (struct sockaddr *) &(rb->params), sizeof(struct sockaddr_ll));
    if(ret < 0){
        err("bind: cannot bind device: %d - ", errno);
        perror("");
        close(sock);
        exit(1);
    }
}

inline void put_dev_into_promisc_mode(int sock, int ifindex)
{
    int ret;
    struct packet_mreq mr;

    memset(&mr, 0, sizeof(struct packet_mreq));

    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
 
    /* this is better than ioctl(), because the kernel now manages the promisc 
       flag for itself */
    ret = setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    if(ret < 0){
        err("setsockopt: cannot set dev %d to promisc mode: %d - ", ifindex, errno);
        perror("");
        close(sock);
        exit(1);
    }
}

inline void inject_kernel_bpf(int sock, struct sock_filter *bpf_code, int len)
{
    int ret;
    struct sock_fprog filter;

    memset(&filter, 0, sizeof(struct sock_fprog));
    
    filter.len = len / sizeof(struct sock_filter);
    filter.filter = bpf_code;
    
    ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
    if(ret < 0){
        err("setsockopt: filter cannot be injected: %d - ", errno);
        perror("");
        close(sock);
        exit(1);
    }
}

inline int ethdev_to_ifindex(int sock, char *dev)
{
    int ret;
    struct ifreq ethreq;

    memset(&ethreq, 0, sizeof(struct ifreq));

    strncpy(ethreq.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sock, SIOCGIFINDEX, &ethreq);
    if(ret < 0){
        err("ioctl: cannot determine dev number for %s: %d - ", ethreq.ifr_name, errno);
        perror("");
        close(sock);
        exit(1);
    }

    return ethreq.ifr_ifindex;
}

inline int mem_notify_user(struct iovec frame)
{
    struct tpacket_hdr *header = frame.iov_base;
    /* important: normally it should be TP_STATUS_USER, but frames larger than 
       our defined framesize will be truncated and set to TP_STATUS_COPY or 
       see other flags as well, so we grab them all in order to get most things 
       working with our stats */ 
    return TP_STATUS_KERNEL != header->tp_status;
}

inline void mem_notify_kernel(struct tpacket_hdr *header)
{
    header->tp_status = TP_STATUS_KERNEL;
}

inline void net_stat(int sock)
{
    int ret;
    socklen_t slen;
    struct tpacket_stats kstats;

    slen = sizeof(struct tpacket_stats);
    memset(&kstats, 0, sizeof(struct tpacket_stats));

    ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
    if(ret > -1){
        dbg("%d frames incoming\n", kstats.tp_packets);
        dbg("%d frames passed filter\n", kstats.tp_packets - kstats.tp_drops);
        dbg("%d frames failed filter (due to out of space)\n", kstats.tp_drops);
    }
}

int alloc_pf_sock()
{
    int sock = socket(PF_PACKET, SOCK_RAW, 0);
    if(sock < 0){
        perror("socket");
        exit(1);
    }
    
    return sock;
}

void parse_rules(char *rulefile, struct sock_filter **bpf, int *len)
{
#define LINE_LEN 512

    int ret;
    int count;
    char buff[LINE_LEN];
    
    struct sock_filter sf_single;

    assert(bpf);

    FILE *fp = fopen(rulefile, "r");
    if(!fp){
        err("cannot read rulefile - ");
        perror("");
        exit(1);
    }
    
    dbg("parsing rulefile %s\n", rulefile);
    
    count = 0;
    while(fgets(buff, LINE_LEN, fp) != NULL){
        memset(&sf_single, 0, sizeof(struct sock_filter));
        
        ret = sscanf(buff, "{ 0x%x, %d, %d, 0x%08x },", (unsigned int *) ((void *) &(sf_single.code)), 
                     (int *) ((void *) &(sf_single.jt)), (int *) ((void *) &(sf_single.jf)), &(sf_single.k));
        if(ret != 4)
            continue;
        
        *len += 1;
        *bpf = (struct sock_filter *) realloc(*bpf, *len * sizeof(struct sock_filter));
        
        memcpy(&(*bpf)[*len - 1],  &sf_single, sizeof(struct sock_filter));
        
        dbg("line %d: { 0x%x, %d, %d, 0x%08x }\n", count++, (*bpf)[*len - 1].code, 
            (*bpf)[*len - 1].jt, (*bpf)[*len - 1].jf, (*bpf)[*len - 1].k);
    }
    
    fclose(fp);
}

void chk_root()
{
    if(geteuid() != 0){
        err("dude, you are not root!\n");
        exit(1);
    }
}

void register_softirq(int sig, void (*handle)(int))
{
    sigset_t block_mask;
    struct sigaction saction;

    sigfillset(&block_mask);

    saction.sa_handler = softirq_hdl;
    saction.sa_mask = block_mask;
    saction.sa_flags = SA_RESTART;

    sigaction(sig, &saction, NULL);
}

inline void hold_softirq()
{
    sigset_t block_mask;

    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    sigaddset(&block_mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &block_mask, NULL);
}

inline void restore_softirq()
{
    sigset_t block_mask;

    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    sigaddset(&block_mask, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
}


int main(int argc, char **argv)
{
    int i, c;
    int sock;
    int ret;
    int bpf_len;
    int print_pckt_v;

    char *pidfile;
    char *logfile;
    char *rulefile;
    char *sockfile;
    char *dev;

    ring_buff_t *rb;
    struct pollfd pfd;
    struct sock_filter **bpf;
    struct itimerval val_r;

    print_pckt_v = 0;
    dev = pidfile = logfile = rulefile = sockfile = NULL;
    while((c = getopt(argc, argv, "vhd:P:L:Df:CS:")) != -1){
        switch(c){
            case 'h':
                help();
                break;
                
            case 'v':
                version();
                break;

            case 'd':
                dev = optarg;
                break;
                
            case 'f':
                rulefile = optarg;
                break;

            case 'C':
                print_pckt_v = 1;
                break;

            case 'D':
                sysdeamon_v = 1;
                break;

            case 'P':
                pidfile = optarg;
                break;

            case 'L':
                logfile = optarg;
                break;

            case 'S':
                sockfile = optarg;
                break;

            case '?':
                if(optopt == 'd')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else if(optopt == 'f')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else if(optopt == 'P')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else if(optopt == 'L')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else if(optopt == 'S')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else if(isprint(optopt))
                    fprintf(stderr, "unknown option `-%c\'\n", optopt);
                else
                    fprintf(stderr, "unknown option character `0x%X\'\n", optopt);
                return 1;

            default:
                abort();
        }
    }

    if(argc < 2 || !dev || !rulefile){
        help();
        exit(1);
    }

    if(sysdeamon_v && (!pidfile || !logfile || !sockfile)){
        help();
        exit(1);    
    }

    for(i = optind; i < argc; i++){
        err("non-option argument %s\n", argv[i]);
    }

    if(optind < argc){
        return 1;
    }

    chk_root();
    register_softirq(SIGINT, &softirq_hdl);
    register_softirq(SIGALRM, &softirq_hdl);
    register_softirq(SIGUSR1, &softirq_hdl);

    if(sysdeamon_v){
        ret = daemonize(pidfile, logfile, sockfile);
        if(ret != 0){
            err("daemonize failed");
            exit(1);
        }
    }

    if(!sysdeamon_v)
        dbg("%s %s\n", PROGNAME_STRING, VERSION_STRING);

    bpf_len = 0;
    bpf = (struct sock_filter **) malloc(sizeof(struct sock_filter *));

    rb = (ring_buff_t *) malloc(sizeof(ring_buff_t));
    memset(rb, 0, sizeof(ring_buff_t));
    memset(&netstat, 0, sizeof(ring_buff_stat_t));

    sock = alloc_pf_sock();
    put_dev_into_promisc_mode(sock, ethdev_to_ifindex(sock, dev));
    
    parse_rules(rulefile, bpf, &bpf_len);
    inject_kernel_bpf(sock, *bpf, bpf_len * sizeof(struct sock_filter));

    create_virt_ring(sock, rb);
    bind_dev_to_ring(sock, ethdev_to_ifindex(sock, dev), rb);
    mmap_virt_ring(sock, rb);

    rb->frames = (struct iovec *) malloc(rb->layout.tp_frame_nr * sizeof(struct iovec));
    for(i = 0; i < rb->layout.tp_frame_nr; ++i){
        rb->frames[i].iov_base = (void *) ((long) rb->buffer) + (i * rb->layout.tp_frame_size);
        rb->frames[i].iov_len = rb->layout.tp_frame_size;
    }

    pfd.fd = sock;
    pfd.revents = i = 0;
    pfd.events = POLLIN | POLLERR;

    /* change_nice(0); */

    val_r.it_value.tv_sec = INTERVAL / 1000;
    val_r.it_value.tv_usec = (INTERVAL * 1000) % 1000000;	
    val_r.it_interval = val_r.it_value;
    
    ret = setitimer(ITIMER_REAL, &val_r, NULL);
    if(ret < 0){
        err("cannot set itimer - ");
        perror("");
        exit(1);
    }
    
    gettimeofday(&netstat.m_start, NULL);
    
    /* this goto shit seems to be pretty ugly, but we do not have 
       branch-predictions within our critical sections thus we won't
       smash the pipeline */
    if(!print_pckt_v)
        goto __j_no_print;

/* __j_print: */
    while(likely(!sigint)){
        while(mem_notify_user(rb->frames[i]) && likely(!sigint)){
            struct frame_map *fm = rb->frames[i].iov_base;
            ring_buff_bytes_t rbb = (unsigned char *) (rb->frames[i].iov_base + sizeof(struct frame_map) + sizeof(short));

            dbg("%d bytes from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n", fm->tp_h.tp_len, 
                rbb[6], rbb[7], rbb[8], rbb[9], rbb[10], rbb[11], rbb[0], rbb[1], rbb[2], rbb[3], rbb[4], rbb[5]);

            /* pending singals will be delivered after netstat manipulation */
            hold_softirq();
            pthread_mutex_lock(&gs_loc_mutex);

            netstat.per_sec.frames++;
            netstat.per_sec.bytes += fm->tp_h.tp_len;

            netstat.total.frames++;
            netstat.total.bytes += fm->tp_h.tp_len;
            
            pthread_mutex_unlock(&gs_loc_mutex);
            restore_softirq();
            
            i = (i + 1) % rb->layout.tp_frame_nr;

            /* this is very important, otherwise poll() does active 
               wait with 100% cpu */
            mem_notify_kernel(&(fm->tp_h));
        }

        poll(&pfd, 1, -1);
    }
    goto __j_out;

__j_no_print:
    while(likely(!sigint)){
        while(mem_notify_user(rb->frames[i]) && likely(!sigint)){
            struct frame_map *fm = rb->frames[i].iov_base;

            /* pending singals will be delivered after netstat manipulation */
            hold_softirq();
            pthread_mutex_lock(&gs_loc_mutex);

            netstat.per_sec.frames++;
            netstat.per_sec.bytes += fm->tp_h.tp_len;
            
            netstat.total.frames++;
            netstat.total.bytes += fm->tp_h.tp_len;
            
            pthread_mutex_unlock(&gs_loc_mutex);
            restore_softirq();

            i = (i + 1) % rb->layout.tp_frame_nr;

            /* this is very important, otherwise poll() does active 
               wait with 100% cpu */
            mem_notify_kernel(&(fm->tp_h));
        }

        poll(&pfd, 1, -1);
    }

__j_out:
    net_stat(sock);
    
    /* restore_nice(); */
    destroy_virt_ring(sock, rb);
    
    free(bpf);
    free(rb);
    close(sock);

    dbg("captured frames: %llu, captured bytes: %llu [%llu KB, %llu MB, %llu GB]\n", netstat.total.frames, 
        netstat.total.bytes, netstat.total.bytes / 1024, netstat.total.bytes / (1024 * 1024), netstat.total.bytes / (1024 * 1024 * 1024));

    if(sysdeamon_v)
        undaemonize(pidfile);
    return 0;
}

