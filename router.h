/* Author: Siddhant Jawa
 *
 *	Email: sjawa@usc.edu
 *	
 */

 #ifndef ROUTER_H
 #define ROUTER_H

/*	NOTE
Minimum frame header-14 bytes
Minimum frame size - 64 bytes
Minimum ip header size- 20bytes
Minimum ip packet size-
Minimum tcp header size-20bytes
Minimum tcp segment size-
Minimum udp header size- 8bytes
Minimum udp datagram size-
*/

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 16

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
	
};


#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* UDP header */
struct sniff_udp {
u_short udp_sport; /* source port */
u_short udp_dport; /* destination port */
u_short udp_hlen; /* Udp header length*/
u_short udp_chksum; /* Udp Checksum */
};

char *dev,errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;				/* Session handle */
	struct bpf_program fp;			/* compiled filter expression */
	char filter_exp[50]="ether proto \\ip";	//"ip proto \\udp or \\tcp or \\icmp";	/* Filter expression */
	bpf_u_int32 mask;			/* netmask of sniffing device */
	bpf_u_int32 net;			/* IP address of const struct pcap_pkthdrsniffing device */
        struct sigaction *act_alarm,*act_int;
	
	struct pcap_pkthdr header;
	const u_char *packet=NULL;


void start_sniffing(void);
void got_packet(u_char*,const struct pcap_pkthdr*,const u_char*);
void create_udp_socket();
void router_log_1(char *);
void router_log_2(char *);
void router_log_3(void);
void INT_handler(int signo);

 #endif