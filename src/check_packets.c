/* 
 * Unix domain socket client for netsniff-ng
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
 */

#define PROGNAME_STRING "check_packets"
#define VERSION_STRING  "0.5.4"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <netsniff-ng.h>

#define DIV_KBYTES(x) ((x) / (1024LLU))
#define DIV_MBYTES(x) ((x) / (1048576LLU))
#define DIV_GBYTES(x) ((x) / (1073741824LLU))

#define DIV_S2DAYS(x)  ((x) / (86400LLU))
#define MOD_DAYS2S(x)  ((x) % (86400LLU))
#define DIV_S2HOURS(x) ((x) / (3600LLU))
#define MOD_HOURS2S(x) ((x) % (3600LLU))
#define DIV_S2MINUT(x) ((x) / (60LLU))
#define MOD_MINUT2S(x) ((x) % (60LLU))

volatile sig_atomic_t nagios_v = 0;

void help()
{
    printf("%s %s, <danborkmann@googlemail.com>\n\n", PROGNAME_STRING, VERSION_STRING);
    printf("%s is a unix domain socket client for netsniff-ng.\n", PROGNAME_STRING);
    printf("\n");
    printf("Options, required:\n");
    printf("    -S <arg>    use file <arg> as uds inode\n");
    printf("\n");
    printf("Options, optional:\n");
    printf("    -N          print stats for Nagios (single line)\n");
    printf("    -v          prints out version\n");
    printf("    -h          prints out this help\n");
    printf("\n");
    printf("Please report bugs to <danborkmann@googlemail.com>\n");
    printf("Copyright (C) 2009 Daniel Borkmann\n");
    printf("License GPLv2: GNU GPL version 2 <http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n");
    exit(1);
}

void version()
{
    printf("%s %s\n\n", PROGNAME_STRING, VERSION_STRING);
    printf("%s is a unix domain socket client for netsniff-ng.\n", PROGNAME_STRING);
    printf("Please report bugs to <dborkman@fbimn.htwk-leipzig.de>\n");
    printf("Copyright (C) 2009 Daniel Borkmann\n");
    printf("License GPLv2: GNU GPL version 2 <http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>\n");
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

int main(int argc, char **argv)
{
    int len;
    int ret;
    int sock;
    int c, i;

    char *sockfile;

    struct sockaddr_un remote;
    ring_buff_stat_t rbs;

    sockfile = NULL;
    while((c = getopt(argc, argv, "vhS:N")) != -1){
        switch(c){
            case 'h':
                help();
                break;
                
            case 'v':
                version();
                break;

            case 'N':
                nagios_v = 1;
                break;

            case 'S':
                sockfile = optarg;
                break;

            case '?':
                if(optopt == 'S')
                    fprintf(stderr, "option -%c requires an argument\n", optopt);
                else
                    fprintf(stderr, "unknown option character `0x%X\'\n", optopt);
                return 1;

            default:
                abort();
        }
    }

    if(argc < 2 || !sockfile){
        help();
        exit(1);
    }

    for(i = optind; i < argc; i++){
        fprintf(stderr, "non-option argument %s\n", argv[i]);
    }

    if(optind < argc){
        return 1;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, sockfile, sizeof(remote.sun_path));
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    ret = connect(sock, (struct sockaddr *) &remote, len);
    if(ret < 0){
        perror("connect");
        exit(1);
    }
    
    ret = recv(sock, &rbs, sizeof(ring_buff_stat_t), 0);
    if(ret <= 0){
        perror("recv client");
        close(sock);
        exit(1);
    }

    close(sock);

    if(nagios_v){
        printf("OK - per second: %llu frames - %llu KB, per minute: %llu frames - %llu KB\n", 
               rbs.s_per_sec.frames, DIV_KBYTES(rbs.s_per_sec.bytes), rbs.s_per_min.frames, DIV_KBYTES(rbs.s_per_min.bytes));
               
        return 0;
    }

    uint64 diff;
    uint64 d_day, d_h, d_min, d_sec;
        
    struct timeval t_curr;

    gettimeofday(&t_curr, NULL);
    
    diff = timespec_sec_diff(&t_curr, &rbs.m_start);
       
    d_day = DIV_S2DAYS(diff);  diff = MOD_DAYS2S(diff);
    d_h   = DIV_S2HOURS(diff); diff = MOD_HOURS2S(diff);
    d_min = DIV_S2MINUT(diff); diff = MOD_MINUT2S(diff);
    d_sec = diff;

    printf("stats summary:\n"); 
    printf("--------------------------------------------------------------------------------------------\n");
    printf("elapsed time: %llu d, %llu h, %llu min, %llu s\n", d_day, d_h, d_min, d_sec); 
    printf("-----------+--------------------------+--------------------------+--------------------------\n");
    printf("           |  per sec                 |  per min                 |  total                   \n");
    printf("-----------+--------------------------+--------------------------+--------------------------\n");
    printf("  frames   | %24llu | %24llu | %24llu \n", rbs.s_per_sec.frames, rbs.s_per_min.frames, rbs.total.frames);
    printf("-----------+--------------------------+--------------------------+--------------------------\n");
    printf("  in B     | %24llu | %24llu | %24llu \n", rbs.s_per_sec.bytes, rbs.s_per_min.bytes, rbs.total.bytes);
    printf("  in KB    | %24llu | %24llu | %24llu \n", DIV_KBYTES(rbs.s_per_sec.bytes), DIV_KBYTES(rbs.s_per_min.bytes), DIV_KBYTES(rbs.total.bytes));
    printf("  in MB    | %24llu | %24llu | %24llu \n", DIV_MBYTES(rbs.s_per_sec.bytes), DIV_MBYTES(rbs.s_per_min.bytes), DIV_MBYTES(rbs.total.bytes));
    printf("  in GB    | %24llu | %24llu | %24llu \n", DIV_GBYTES(rbs.s_per_sec.bytes), DIV_GBYTES(rbs.s_per_min.bytes), DIV_GBYTES(rbs.total.bytes));
    printf("-----------+--------------------------+--------------------------+--------------------------\n");

    return 0;
}

