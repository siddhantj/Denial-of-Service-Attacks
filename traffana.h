/* Author: Siddhant Jawa
 *
 *	Email: sjawa@usc.edu
 *	
 */

#ifndef TRAFFANA_H
#define	TRAFFANA_H

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

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

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
        #define IP_DF 0x4000            /* don't fragment flag */
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

/* ICMP header */
struct sniff_icmp
{
u_char icmp_type;
u_char icmp_code;
u_short icmp_checksum;
};
/* struct to fetch machine address */
struct ifaddrs *addr;

struct list
{
    struct sniff_ip ip_header;  /* Pointer to ip_header */
    struct list *next;      /* pointing to next ip_header */
};
struct list *start;

typedef struct sources
{
        char source_ip[30];
    struct sources *next;
}source_list;



source_list *source_start,*source_ptr,*source_prevptr,*source_newptr;

void handle_commandline(int argc,char *argv[]);
void got_packet(u_char*,const struct pcap_pkthdr*,const u_char*);
void read_from_file(struct pcap_pkthdr*);
void print_readfile_stats(long,long);
void alarm_printhandler(int signo);
void INT_handler(int signo);
void handleTrack_2(const u_char*);
void handleTrack_5(const u_char*);
int print_no_of_flows(void);
void free_flow_linked_list(void);
void free_zero(void);
void check_attack(void);	/* flag_check_attack */
void attack_occured(void);
void add_sources(const u_char *);
void free_source_linked_list(void);


int flag_pktthresh=0,flag_byte_thresh=0,flag_flowthresh=0,flag_sourcethresh=0; /* set them when it exceeds threshold */
long int pkt_count,flow_count,byte_count,source_count;				/* and count parameters for assignment 3*/
int flag_packet=0,flag_byte=0,flag_flow=0,flag_source=0;
int total_source=0;
FILE *fd_attack;
int flag_check_attack=1;
struct timeval attack_current_time;
char filename[100];
char my_ip[30];


#endif

