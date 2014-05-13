#include <signal.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "traffana.h"


#define _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED

int total_count=0,count_tcp=0,count_udp=0,count_icmp=0,count_default=0;
static unsigned int total_bytes=0;
int err_loop;	/* check error condition pcap_loop */
int flag_verbose=0,flag_z=0;
int long sec1=0,usec1=0,sec2=0,usec2=0;

struct itimerval *newvalue;
struct timeval current_time;
int **dlt_buf;

/*Global arguments for command-line */
char interface[10];
char *read_file= NULL;
char *write_file = NULL;
int epoch=1;
useconds_t usec_sleep=0;
FILE* filew, *filer;				/* file pointer */
int no_of_flows=0;
int tcp_flow=0,udp_flow=0,icmp_flow=0;
int z_value=0;





int main(int argc,char *argv[])
{
	char *dev,errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;				/* Session handle */
	struct bpf_program fp;			/* compiled filter expression */
	char filter_exp[]="ether proto \\ip";	//"ip proto \\udp or \\tcp or \\icmp";	/* Filter expression */
	bpf_u_int32 mask;			/* netmask of sniffing device */
	bpf_u_int32 net;			/* IP address of const struct pcap_pkthdrsniffing device */
        struct sigaction *act_alarm,*act_int;
	
	struct pcap_pkthdr header;
	const u_char *packet=NULL;


	act_alarm=(struct sigaction*)malloc(sizeof(struct sigaction));
	act_int=(struct sigaction*)malloc(sizeof(struct sigaction));	
	memset(act_alarm,'\0',sizeof(act_alarm));
	memset(act_int,'\0',sizeof(act_int));
	
	act_alarm->sa_handler=alarm_printhandler;	
	sigemptyset(&act_alarm->sa_mask);
	act_alarm->sa_flags=0;	
	sigaction(SIGALRM,act_alarm,NULL);
	
	act_int->sa_handler=INT_handler;
	sigemptyset(&act_int->sa_mask);
	act_int->sa_flags=0;
	sigaction(SIGINT,act_int,NULL);	
	
	
	if(gettimeofday(&current_time,NULL) != 0)
	{
		fprintf(stderr,"Error in gettimeofday(): %s\n",strerror(errno));
		exit(1);
	} 
	
	/* Handle commandline here */
	
	memset(interface,'\0',sizeof(interface));
	memset(filename,'\0',sizeof(filename));
	memset(my_ip,'\0',sizeof(my_ip));

	handle_commandline(argc,argv);
	
	newvalue=(struct itimerval*)malloc(sizeof(struct itimerval));
	newvalue->it_interval.tv_sec=epoch;
	newvalue->it_interval.tv_usec=0;
	newvalue->it_value.tv_sec=epoch;
	newvalue->it_value.tv_usec=0;
	setitimer(ITIMER_REAL,newvalue,NULL);  

	/* fetch ip address */
	getifaddrs(&addr);
	while(addr)
	{
		if(addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET && strcmp(addr->ifa_name,interface)==0)
		{
			struct sockaddr_in *paddr = (struct sockaddr_in *)addr->ifa_addr;
			//fprintf(stdout,"%s %s\n",addr->ifa_name,inet_ntoa(paddr->sin_addr));  //project
			strcpy(filename,inet_ntoa(paddr->sin_addr));
			strcpy(my_ip,inet_ntoa(paddr->sin_addr));
			break;
		}
		addr = addr->ifa_next;
	}
	//printf("Filename: %s",filename);
	if(epoch == 0)
	{
		epoch=1;	// default is 1 sec
	}
	if(interface[0] == '\0')
	{
		dev=" ";
	}
	else
	{
		dev=interface;
	}
	
	//fprintf(stdout,"Device is %s\n",dev);
	
	/* Lookup network */
	if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
	{
		 //fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	} 
	//printf("IP: %d\n",net);
	//printf("Mask: %d\n",mask);	

	 /* Opening device for sniffing */
	if(read_file == NULL)
	{
								
		if((handle=pcap_create(dev,errbuf)) == NULL)
		{
			fprintf(stderr,"Error in pcap_create: %s",errbuf);
			exit(1);
		}
		if(pcap_set_promisc(handle,5) == PCAP_ERROR_ACTIVATED || pcap_set_timeout(handle,epoch*1000) == PCAP_ERROR_ACTIVATED )
		{
			fprintf(stderr,"Capture handle already activated");
			exit(1);
		}
		
		pcap_activate(handle);  
		
	}
	else
	{
		filer=fopen(read_file,"r");
		/* block the alarm handler too */
		sigaddset(&act_alarm->sa_mask,SIGALRM);
		sigprocmask(SIG_BLOCK,&act_alarm->sa_mask,NULL);		
		if(filer == NULL)
		{
			perror("Error in fopen file");
			exit(1);
		}
				
		handle=pcap_fopen_offline(filer,errbuf);
		if(handle == NULL)
		{
			fprintf(stderr,"Error in pcap_open_offline(): %s",errbuf);
			exit(1);
		}
		
	}
	if(write_file != NULL)
	{
		filew=fopen(write_file,"w");			
	}
		
	if(handle == NULL)
	{
		fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
		exit(1);
	}
	
	
	/* Determine the type of link-headers the device provides */
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename]\n");
		exit(1);
	}

	/* Complie filter */
	if(pcap_compile(handle,&fp, filter_exp,0,net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	/* Set filter */
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 exit(1);
	}
	/* set the diection */
	//pcap_setdirection(handle,PCAP_D_IN);

	
	

	/* Grab the packets */
	if(read_file == NULL)
	{
		err_loop=pcap_loop(handle,-1,got_packet,(u_char *)filew);	// count -1 or 0 for infinity packets AND pass argument the name
									// of th file
		if(err_loop == -1)
		{
			pcap_perror(handle,errbuf);
			fprintf(stderr,"Error in pcap_loop(): %s\n",errbuf);
			exit(1);
		}
	}
	
	if(read_file !=NULL)
	{
		
		while((packet = pcap_next(handle,&header))!=NULL)
		{
			got_packet(0,&header,packet);
		}
	}

	/* Close session */
	
	if(read_file != NULL)
	{
		print_readfile_stats(sec1,usec1);	/* to read the last epoch */	
	}
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;

}

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	struct pcap_pkthdr new_header;
	new_header= *header;
	int size_ip;
	//int size_tcp;
	//int size_udp;
	//int size_icmp;
					/*new_header=(struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr*));
					new_header->ts=header->ts;
					new_header->caplen = header->caplen;
					new_header->len = header->len; */ 
					/* Structures to packet headers */
					//const struct sniff_ethernet *ethernet_header;
	const struct sniff_ip *ip_header;
	//const struct sniff_tcp *tcp_header;
	//const struct sniff_udp *udp_header;
	ip_header=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip=IP_HL(ip_header)*4;
	if (size_ip < 20) 
	{
		fprintf(stderr,"   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	if(read_file != NULL)
	{
		read_from_file(&new_header);
		/* free(new_header); */
	} 
	if(flag_z == 1)
	{
		if(z_value == 2)		
			handleTrack_2(packet);
		if(z_value == 5)
			handleTrack_5(packet);
	}
	//ethernet_header=(struct sniff_ethernet*)packet;
	
	total_count++;	
	/* Determine protocol */
	switch(ip_header->ip_p)
	{
		case IPPROTO_TCP:
			count_tcp++;
			break;
		case IPPROTO_UDP:
			count_udp++;
			break;
		case IPPROTO_ICMP:
			count_icmp++;
			break;
		case IPPROTO_IP:
			break; 
		default:
			count_default++;	
			
	}
	total_bytes = total_bytes + header->len;
	add_sources(packet);
	/* check for attack */
	if(flag_packet==1 || flag_byte==1 /*|| flag_flow==1*/ || flag_source==1)
	{
		if(flag_check_attack==1)
			check_attack();
	}
	
}

void check_attack()
{
	
	if(flag_packet==1)
	{
		if(total_count > pkt_count)
		{
			fprintf(stdout,"Attack occured\n");		
			/* Measure the current time when the threshold crossed */
			if(gettimeofday(&attack_current_time,NULL) != 0)
			{
				fprintf(stderr,"Error in gettimeofday(attack_current_time): %s\n",strerror(errno));
				exit(1);
			}
			flag_packet=99;			
			//flag_check_attack=0; 		
			attack_occured();
		}
	}
	
	  if(flag_byte==1)
	 {
		if(total_bytes > byte_count)
		{
			fprintf(stdout,"Attack occured\n");		
			/* Measure the current time when the threshold crossed */
			if(gettimeofday(&attack_current_time,NULL) != 0)
			{
				fprintf(stderr,"Error in gettimeofday(attack_current_time): %s\n",strerror(errno));
				exit(1);
			}
			flag_byte=99;			
			//flag_check_attack=0; 		
			attack_occured();
		}
	 }

	 if(flag_flow==1)
	{
		if(no_of_flows > flow_count)
		{
			fprintf(stdout,"Attack occured\n");		
			/* Measure the current time when the threshold crossed */
			if(gettimeofday(&attack_current_time,NULL) != 0)
			{
				fprintf(stderr,"Error in gettimeofday(attack_current_time): %s\n",strerror(errno));
				exit(1);
			}
			flag_flow=99;		
			//flag_check_attack=0; 		
			attack_occured();
		}
	}

	 if(flag_source == 1)
	{
		if(total_source > source_count)
		{
			fprintf(stdout,"Attack occured\n");		
			/* Measure the current time when the threshold crossed */
			if(gettimeofday(&attack_current_time,NULL) != 0)
			{
				fprintf(stderr,"Error in gettimeofday(attack_current_time): %s\n",strerror(errno));
				exit(1);
			}
			flag_source=99;			
			//flag_check_attack=0; 		
			attack_occured();
		}
	}
}

void attack_occured()
{
		
	//char attack_buf[100];
	//memset(attack_buf,'\0',sizeof(attack_buf));
	    char hostname[1024];
        memset(hostname,'\0',sizeof(hostname));
        gethostname(hostname, 1023);
      
        struct hostent* h;
        h = gethostbyname(hostname);
	if(fd_attack==NULL)
	{
		sprintf(filename,"%s.attackinfo",h->h_name);
		fd_attack=fopen(filename,"w");
		fprintf(fd_attack,"CURRENT TIME                 START TIME                   PACKETS         BYTES            FLOWS	SOURCE		\n");
	}
	
	//memset(attack_buf,'\0',sizeof(attack_buf));
	fprintf(fd_attack,"%lu.%ld            %lu.%ld            %d            %d            %d              %d	\n",attack_current_time.tv_sec,attack_current_time.tv_usec, 						current_time.tv_sec,current_time.tv_usec,total_count,total_bytes,no_of_flows,total_source);
	exit(0);	// exit traffana tool		
}


void alarm_printhandler(int signo)
{
	
		//fprintf(stdout,"Source_count:%d\n",total_source);	// project
		if(write_file == NULL)
		{
			printf("%lu.%ld ",current_time.tv_sec,current_time.tv_usec); 
			printf(" %d	%u	",total_count,total_bytes);
			
			if(flag_z==1)
			{
				printf("%d	",no_of_flows);
			}
			/* If -v is supplied */
			if(flag_verbose == 1)
			{
				fprintf(stdout,"%d	%d	%d	%d",count_tcp,count_udp,count_icmp,count_default);
				if(flag_z==1)
				{	
					printf("	%d	%d\n",tcp_flow,udp_flow);
					//free_zero();  CHANGED ON 04/19/14
				}
				else
				{
					printf("\n");
				}
				free_zero();	//PREVIOUSLY ON 411
			}
			else
			{
				printf("\n");
				/* Free the linked list */
				free_zero();
				
			}
		}
		else
		{
			fprintf(filew,"%lu.%ld ",current_time.tv_sec,current_time.tv_usec);
			fprintf(filew," %d	%u 	",total_count,total_bytes);
			if(flag_z==1)
			{
				fprintf(filew,"%d	",no_of_flows);
			}		
			/* If -v is supplied */
			if(flag_verbose == 1)
			{
				fprintf(filew,"%d	%d	%d	%d",count_tcp,count_udp,count_icmp,count_default);
				if(flag_z==1)
				{
					fprintf(filew,"	%d	%d\n",tcp_flow,udp_flow);
					free_zero();
				}
				else
				{
					fprintf(filew,"\n");
				}
				
			}
			else
			{
				fprintf(filew,"\n");
				/* Free the linked list */
				if(flag_z==1)
					free_zero();
			}
		}		
		
		current_time.tv_sec=current_time.tv_sec + epoch;	/* this is the start time */
		total_count=0;
		total_bytes=0;
		count_tcp=0;
		count_udp=0;
		count_icmp=0;
		count_default=0; 
		
	
}

void add_sources(const u_char *packet)
{
	struct sniff_ip *ip_header;
	char source[30],destination[30];
	memset(source,'\0',sizeof(source));
	memset(destination,'\0',sizeof(destination));
	ip_header= (struct sniff_ip*)(packet + SIZE_ETHERNET);
	strcpy(source,inet_ntoa(ip_header->ip_src));
	strcpy(destination,inet_ntoa(ip_header->ip_dst));
	
	if(strcmp(destination,my_ip) == 0)
	{
		//fprintf(stdout,"Source: %s	Destination: %s\n",source,destination);
		if(source_start == NULL)
		{
			source_start=(source_list *)malloc(sizeof(source_list));
			strcpy(source_start->source_ip,source);
			source_start->next=NULL;
			total_source++;
		
		}
		else
		{
			source_ptr=source_start;
		
			while(source_ptr!=NULL)
			{
				source_prevptr=source_ptr;
				if(strcmp(source,source_ptr->source_ip) == 0)
				{
					return;
				}
				source_ptr=source_ptr->next;
			}
			source_newptr=(source_list*)malloc(sizeof(source_list));
			source_prevptr->next=source_newptr;
			strcpy(source_newptr->source_ip,source);
			source_newptr->next=NULL;
			total_source++;		
		
		}	
	}
	
	
}

void handleTrack_2(const u_char *packet)
{
		
	struct sniff_ip ip,*ip_header;
	struct list *ptr=NULL,*new_ip_header=NULL,*prevptr;
	char source[30],destination[30],packet_source[20],packet_destination[20];
	//u_char protocol;

	memset(source,'\0',sizeof(source));
	memset(destination,'\0',sizeof(destination));
	memset(packet_source,'\0',sizeof(packet_source));
	memset(packet_destination,'\0',sizeof(packet_destination));
	ip_header=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	ip=*ip_header;
	
	strcpy(source,inet_ntoa(ip.ip_src));	
	strcpy(destination,inet_ntoa(ip.ip_dst));
	//protocol=ip.ip_p;
	
	if(start==NULL)
	{
		start=(struct list*)malloc(sizeof(struct list));
		start->ip_header=ip;
		start->next=NULL;
		no_of_flows=1;
		/*fprintf(stdout,"*********This is the first packet of an epoch********\n");
		fprintf(stdout,"Source: %s\n",inet_ntoa(ip.ip_src));
		fprintf(stdout,"Destination: %s\n",inet_ntoa(ip.ip_dst));*/
		
		if(ip.ip_p == IPPROTO_TCP)
		{			
			tcp_flow=1;	// doesn't work when tcp_flow++
			//fprintf(stdout,"Protocol:TCP\n\n");
		}		
			else if(ip.ip_p == IPPROTO_UDP)
			{
				udp_flow=1;	// doesn't work when udp_flow++
				//fprintf(stdout,"Protocol:UDP\n\n");
			}			
			else if(ip.ip_p == IPPROTO_ICMP)
			{	icmp_flow=1;
				//fprintf(stdout,"Protocol:ICMP\n\n");
			}
	}
	else
	{
		//new_ip_header=(struct list*)malloc(sizeof(struct list));
		ptr=start;
		while(ptr!=NULL)
		{
			prevptr=ptr;
			//strcpy(packet_source,inet_ntoa(prevptr->ip_header.ip_src));		
			//strcpy(packet_destination,inet_ntoa(prevptr->ip_header.ip_dst));
						
			if(strcmp(source,inet_ntoa(prevptr->ip_header.ip_src))==0 && strcmp(destination,inet_ntoa(prevptr->ip_header.ip_dst))==0 
					/*&& /protocol == (u_char)prevptr->ip_header.ip_p*/)
			{
				//free(new_ip_hea12	der);				
				return;
			}
						
			ptr=ptr->next;	
		}
			new_ip_header=(struct list*)malloc(sizeof(struct list));
			prevptr->next=new_ip_header;
			new_ip_header->ip_header=ip;			
			new_ip_header->next = NULL;
			/*fprintf(stdout,"Source: %s\n",inet_ntoa(ip.ip_src));
			fprintf(stdout,"Destination: %s\n",inet_ntoa(ip.ip_dst));b*/
			no_of_flows++;
			if(ip.ip_p == IPPROTO_TCP)
			{	tcp_flow++;
				//fprintf(stdout,"Protocol:TCP\n\n");
			}
			else if(ip.ip_p == IPPROTO_UDP)
			{	udp_flow++;
				//fprintf(stdout,"Protocol:UDP\n\n");
			}
			else if(ip.ip_p == IPPROTO_ICMP)
			{	icmp_flow++;
				//fprintf(stdout,"Protocol:ICMP\n\n");
			}			
	}
	
} 

void handleTrack_5(const u_char *packet)
{
	struct sniff_ip ip,*ip_header;
	struct sniff_tcp tcp;
	int size_ip;
	struct list *ptr=NULL,*new_ip_header=NULL,*prevptr;
	char source[20],destination[20],packet_source[20],packet_destination[20];
	int source_port=0,destination_port=0;
	u_char protocol;

	memset(source,'\0',sizeof(source));
	memset(destination,'\0',sizeof(destination));
	memset(packet_source,'\0',sizeof(packet_source));
	memset(packet_destination,'\0',sizeof(packet_destination));

	ip_header=(struct sniff_ip*)(packet + SIZE_ETHERNET);
	ip=*ip_header;
	strcpy(source,inet_ntoa(ip.ip_src));
	strcpy(destination,inet_ntoa(ip.ip_dst));

	size_ip=IP_HL(ip_header)*4;
	tcp=*((struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip));
	source_port=ntohs(tcp.th_sport);
	destination_port=ntohs(tcp.th_dport);
	protocol=(u_char)ip.ip_p;

	/*if(protocol==IPPROTO_ICMP)
	{
		//fprintf(stdout,"icmp ignored\n");
		return;
	}*/
	
	if(start==NULL)
	{
		start=(struct list*)malloc(sizeof(struct list));
		start->ip_header=ip;
		start->next=NULL;
		no_of_flows=1;
		if(ip.ip_p == IPPROTO_TCP)
			tcp_flow=1;	// doesn't work when tcp_flow++
		if(ip.ip_p == IPPROTO_UDP)
			udp_flow=1;	// doesn't work when udp_flow++
	}
	else
	{
		//new_ip_header=(struct list*)malloc(sizeof(struct list));
		ptr=start;
		while(ptr!=NULL)
		{
			prevptr=ptr;
			strcpy(packet_source,inet_ntoa(prevptr->ip_header.ip_src));		//inet_ntoa(prevptr->ip_header.ip_src)
			strcpy(packet_destination,inet_ntoa(prevptr->ip_header.ip_dst));	//inet_ntoa(prevptr->ip_header.ip_dst)
			size_ip=IP_HL(&prevptr->ip_header)*4;
			tcp=*((struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip));
			if(protocol == IPPROTO_ICMP)
			{
				if(strcmp(source,inet_ntoa(prevptr->ip_header.ip_src))==0 && strcmp(destination,inet_ntoa(prevptr->ip_header.ip_dst))==0 && protocol == (u_char)prevptr->ip_header.ip_p)
			{
				//free(new_ip_header);				
				return;
			}	
			}
			else
			{						
			if(strcmp(source,packet_source)==0 && strcmp(destination,packet_destination)==0 && source_port == ntohs(tcp.th_sport)
				&& destination_port == ntohs(tcp.th_dport) && protocol == prevptr->ip_header.ip_p )
			{
				//free(new_ip_header);				
				return;
			}
			}
						
			ptr=ptr->next;	
		}
			new_ip_header=(struct list*)malloc(sizeof(struct list));
			prevptr->next=new_ip_header;
			new_ip_header->ip_header=ip;			
			new_ip_header->next = NULL;
			no_of_flows++;
			if(ip.ip_p == IPPROTO_TCP)
				tcp_flow++;
			if(ip.ip_p == IPPROTO_UDP)
				udp_flow++;
	}
	

} 

void handle_commandline(int argc,char *argv[])
{

int i;
char *ptr;
	
	if(argc==1)
	{
		fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename]\n");
		exit(1);
	}
	
	for(i=1;i<argc;i=i+2)
	{
		if(strcmp(argv[i],"-i") == 0 || strcmp(argv[i],"--int") ==0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename]\n");
				exit(1);
			}			
			strcpy(interface,argv[i+1]);
			continue;
		}
		

		if(strcmp(argv[i],"-T")==0 || strcmp(argv[i],"--time") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename]\n");
				exit(1);
			}				
			ptr=argv[i+1];
			epoch=atoi(ptr); /* converted to int but ascii value is assigned */
			//epoch=epoch-48;	 /* ASCII value of 0 is 48 */	
			usec_sleep=epoch*1000000;
			continue;		
			
		}
		
		if(strcmp(argv[i],"-r") == 0 || strcmp(argv[i],"--read") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}				
			read_file=argv[i+1];
			continue;
		}
		if(strcmp(argv[i], "-z") == 0 || strcmp(argv[i],"--track") == 0)
		{
				if(argv[i+1] == NULL || *argv[i+1] =='-')
				{
					fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}] \n");
					exit(1);
				}
				if(strcmp(argv[i+1],"2")==0 || strcmp(argv[i+1],"5")==0)
				{
					flag_z=1;
					z_value=atoi(argv[i+1]);
					continue;
				}
				else
				{
					fprintf(stderr,"Wrong parameter of z supplied");
					exit(1);
				}
		
										
		}
		if(strcmp(argv[i],"-p") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}
			pkt_count=atoi(argv[i+1]);
			flag_packet=1;
			continue;
				
		}
		if(strcmp(argv[i],"-b") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}
			byte_count=atoi(argv[i+1]);
			flag_byte=1;
			continue;
		}
		if(strcmp(argv[i],"-f") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}
			flow_count=atoi(argv[i+1]);
			flag_flow=1;
			continue;
		}
		if(strcmp(argv[i],"-s") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}
			source_count=atoi(argv[i+1]);	
			flag_source=1;
			continue;
		}	
		if(strcmp(argv[i],"-w") == 0 || strcmp(argv[i],"--write") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-')
			{
				fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
				exit(1);
			}				
			write_file=argv[i+1];
			continue;
		}
			
		/* read and wrte cannot simultaneously work each other */ 
		if(strcmp(argv[i],"-v") ==0 || strcmp(argv[i],"--verbose") == 0) 
		{
			flag_verbose=1;
			i--;
			continue;
		}
		
		else
		{
			fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
			exit(1);
		}
			
		
	}
		if(strlen(interface)!=0 && read_file != NULL)
		{
			//fprintf(stderr,"Read and capture cannot work together\n");	
			fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
			exit(1);
		}
		/*if(read_file != NULL && write_file != NULL)
		{
			fprintf(stderr,"read and write cannot work together\n");			
			fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
			exit(1);
		}*/
		if(strlen(interface) == 0 && (write_file != NULL || flag_verbose ==1) && read_file == NULL )
		{	
			//fprintf(stderr,"Need interface to capture\n");
			fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename][-z{2|5}]\n");
			exit(1);
		}
		
}
		

void read_from_file(struct pcap_pkthdr *header)
{
float sec_dif=0,usec_dif=0;
static int first_packet_flag=0;

	if(first_packet_flag==0)
	{
		sec1=header->ts.tv_sec;
		usec1=header->ts.tv_usec;
		sec2=sec1;
		usec2=usec1;
		first_packet_flag=1;
	}
	else
	{
		sec2=header->ts.tv_sec;
		usec2=header->ts.tv_usec;
	}
	sec_dif=sec2 - sec1;
	usec_dif=usec2 - usec1;
	if((sec_dif*1000000) + usec_dif <=epoch*1000000)
	{
		// do nothing 
	}
	else
	{
		sec1=sec1 + epoch;
		usec1=usec1 + 0;		
		print_readfile_stats(sec1-epoch,usec1);		// coz you have to print from the start time
		total_count=0;
		total_bytes=0;
		count_tcp=0;
		count_udp=0;
		count_icmp=0;
		count_default=0;
		while((sec2-sec1)*1000000 +(usec2 -usec1) > epoch*1000000)
		{
			if(read_file!=NULL && write_file==NULL)
			{			
				//no_of_flows=0;			
				sec1=sec1 + epoch; 
				usec1=usec1 + 0;
				printf(" %ld.%ld ",sec1-epoch,usec1);
				printf(" %d 	%d 	",total_count,total_bytes);
				if(flag_z==1)
				{
					printf("%d	",no_of_flows);
				}
				if(flag_verbose == 1)
				{
					printf("%d 	%d 	%d 	%d",count_tcp,count_udp,count_icmp,count_default);
					if(flag_z==1)
					{
						printf("	%d	%d	\n",tcp_flow,udp_flow/*,icmp_flow */);
						free_zero();
					}
					else
					{
						printf("\n");
					}				
				
				}
				else
				{
					printf("\n");
					/* Free the linked list */
					free_zero();
				}
			}
			if(read_file!=NULL && write_file!=NULL)
			{
				//no_of_flows=0;			
				sec1=sec1 + epoch; 
				usec1=usec1 + 0;
				fprintf(filew," %ld.%ld ",sec1-epoch,usec1);
				fprintf(filew," %d 	%d 	",total_count,total_bytes);
				if(flag_z==1)
				{
					fprintf(filew,"%d	",no_of_flows);
				}
				if(flag_verbose == 1)
				{
					fprintf(filew,"%d 	%d 	%d 	%d",count_tcp,count_udp,count_icmp,count_default);
					if(flag_z==1)
					{
						fprintf(filew,"	%d	%d	\n",tcp_flow,udp_flow/*,icmp_flow */);
						free_zero();
					}
					else
					{
						fprintf(filew,"\n");
					}				
				
				}
				else
				{
					fprintf(filew,"\n");
					/* Free the linked list */
					free_zero();
				}
			}	
		}	
	}	
}

void free_flow_linked_list()
{
	struct list *ptr=start,*free_ptr;
	while(ptr!=NULL)
	{
		free_ptr=ptr;
		ptr=ptr->next;
		free_ptr->next=NULL;
		free(free_ptr);
		
	}
	start=NULL;
}

void free_source_linked_list()
{
	 source_list *ptr=source_start,*free_ptr;
	while(ptr!=NULL)
	{
		free_ptr=ptr;
		ptr=ptr->next;
		free_ptr->next=NULL;
		free(free_ptr);
	}
	source_start=NULL;
}

void free_zero()
{
	free_flow_linked_list();
	free_source_linked_list();
	no_of_flows=0;
	total_source=0;
	tcp_flow=0;
	udp_flow=0;
	icmp_flow=0;
	//flag_check_attack=1;
	if(flag_packet==99)
		flag_packet=1;
	if(flag_byte==99)
		flag_byte=1;
	if(flag_flow==99)
		flag_flow=1;
	if(flag_source==99)
		flag_source=1;
}	

void INT_handler(int signo)
{
	if(write_file != NULL)
	{
		fclose(filew);
	//	exit(0);
	}
	if(read_file != NULL)
	{
		fclose(filer);	
	//	exit(0);
	}
	if(fd_attack!= 0)
	{
		fclose(fd_attack);
	}
	
	
		exit(0);	// use free_code and pcap_close()
	
}

void print_readfile_stats(long sec1,long usec1)
{
	if(read_file!=NULL && write_file==NULL)
	{	
		fprintf(stdout," %ld.%ld ",sec1,usec1);
		fprintf(stdout," %d  %d  	",total_count,total_bytes);
		if(flag_z==1)
		{
			printf("%d	",no_of_flows);
		}
		/* If -v is supplied */
		if(flag_verbose == 1)
		{
			fprintf(stdout,"%d 	%d 	%d 	%d",count_tcp,count_udp,count_icmp,count_default);
			if(flag_z==1)
			{
				fprintf(stdout,"	%d	%d	\n",tcp_flow,udp_flow/*,icmp_flow*/);
				free_zero();
			}
			else
			{
				printf("\n");
			}	
		}
		else
		{
			printf("\n");
			/*Free linked list */
			free_zero();
		}
	}
	if(read_file!=NULL && write_file!=NULL)
	{
		fprintf(filew," %ld.%ld ",sec1,usec1);
		fprintf(filew," %d  %d  	",total_count,total_bytes);
		if(flag_z==1)
		{
			fprintf(filew,"%d	",no_of_flows);
		}
		/* If -v is supplied */
		if(flag_verbose == 1)
		{
			fprintf(filew,"%d 	%d 	%d 	%d",count_tcp,count_udp,count_icmp,count_default);
			if(flag_z==1)
			{
				fprintf(filew,"	%d	%d	\n",tcp_flow,udp_flow/*,icmp_flow*/);
				free_zero();
			}
			else
			{
				fprintf(filew,"\n");
			}	
		}
		else
		{
			fprintf(filew,"\n");
			/*Free linked list */
			free_zero();
		}
	}		

}
	
		

