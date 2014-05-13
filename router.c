#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <signal.h>
#include <errno.h>
#include "router.h"
#include <time.h>
#include <math.h>


#define _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED

int epoch;
double prob;
int tcp_port,udp_port;
char my_ip[30], endhost_ip[30];
struct ifaddrs *addr;
int err_loop;
struct sockaddr_in serv_addr, cli_addr;
FILE * fp_router_log = NULL;
int flag_2=1;

struct timeval start_traceback_time;
int no_of_traceback_packet=0;
char hostname[50];

struct sigaction *act_in;

 /* UDP client */
    int udp_sockfd;                 
    struct sockaddr_in endhost_servaddr;
    struct hostent *endhost_server;
    char udp_buffer[50];
    char tcp_buffer[256];


void handle_commandline(int argc, char * argv[]);
void get_ip(void);
void start_marking(void);

int main( int argc, char *argv[] )
{
    
    int tcp_sockfd, tcp_newsockfd, clilen;		
    
    int n;
      
    handle_commandline(argc,argv);
    act_int=(struct sigaction*)malloc(sizeof(struct sigaction));

    memset(tcp_buffer,'\0',sizeof(tcp_buffer));
    memset(udp_buffer,'\0',sizeof(udp_buffer));
    memset(my_ip,'\0',sizeof(my_ip));
    memset(act_int,'\0',sizeof(act_int));
    memset(hostname,'\0',sizeof(hostname));
    //memset(filter_exp,'\0',sizeof(filter_exp));

    //get_ip();
    
    act_int->sa_handler=INT_handler;
    sigemptyset(&act_int->sa_mask);
    act_int->sa_flags=0;
    sigaction(SIGINT,act_int,NULL);

    gethostname(hostname,1023);
    struct hostent *h;
     h = gethostbyname(hostname);
     strcpy(my_ip,h->h_name);
     //printf("%s ",my_ip); // project

    /*************** Create a TCP server *******************/
    tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sockfd < 0) 
    {
        perror("ERROR opening socket");
        exit(1);
    }
    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr =  INADDR_ANY;       //inet_addr(my_ip);
    serv_addr.sin_port = htons(tcp_port);
 
    /*  bind() call.*/
    if (bind(tcp_sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
    {
         perror("ERROR on binding");
         exit(1);
    }

    /* Now start listening    */
    listen(tcp_sockfd,5);
    clilen = sizeof(cli_addr);

    //fprintf(stdout,"Waiting for accept\n");   //project

    /* Accept actual connection from the client */
    tcp_newsockfd = accept(tcp_sockfd, (struct sockaddr *)&cli_addr,(socklen_t*)&clilen);
    strcpy(endhost_ip,(inet_ntoa(cli_addr.sin_addr)));
    if (tcp_newsockfd < 0) 
    {
        perror("ERROR on accept");
        exit(1);
    }
     /*If connection is established then start communicating */
    	bzero(tcp_buffer,256);
  		n = read(tcp_newsockfd,tcp_buffer,255 );
    	if (n < 0)
    	{
    	    perror("ERROR reading from socket");
    	    exit(1);
    	}
    	// printf("Here is the message: %s\n",tcp_buffer); //project
        if(strcmp(tcp_buffer,"SM") == 0)
        {
            
            router_log_1(endhost_ip);
            close(tcp_sockfd);
            create_udp_socket();
           // sleep(2);
            start_sniffing();
        } 
        else    // this statement is not needed 
        {
            close(tcp_sockfd);    
        } 
        start_sniffing();
return 0; 
}

void start_sniffing()
{
    //memset(filter_exp,'\0',sizeof(filter_exp));
   // sprintf(filter_exp,"ip dest %s",inet_ntoa(cli_addr.sin_addr));
    /* Lookup network */
    if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
    {
         //fprintf(stderr, "Can't get netmask for device %s\n", dev);
         net = 0;
         mask = 0;
    } 

     handle = pcap_open_live("any", SNAP_LEN, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    } 
    /*if((handle=pcap_create("any",errbuf)) == NULL)    //NULL-> capture from all interfaces
    {
        fprintf(stderr,"Error in pcap_create: %s",errbuf);
        exit(1);
    }
    if(pcap_set_promisc(handle,5) == PCAP_ERROR_ACTIVATED  )
    {
       fprintf(stderr,"Capture handle already activated");
       exit(1);
    }
        
    pcap_activate(handle);

    if(handle == NULL)
    {
        fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
        exit(1);
    } */

    /* Determine the type of link-headers the device provides */
    if(pcap_datalink(handle) != DLT_LINUX_SLL)   //DLT_EN10MB
    {
        fprintf(stderr,"Usage: ./traffana -v [-r filename] [-i interface] [-T epoch] [-w filename]\n");
        exit(1);
    } 

    /* Complie filter */
    if(pcap_compile(handle,&fp, filter_exp,1,0) == -1)
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

    // set direction
    pcap_setdirection(handle,PCAP_D_IN);

    err_loop=pcap_loop(handle,-1,got_packet,(u_char *)NULL);
    if(err_loop == -1)
    {
        pcap_perror(handle,errbuf);
        fprintf(stderr,"Error in pcap_loop(): %s\n",errbuf);
        exit(1);
    }

    pcap_freecode(&fp);
    pcap_close(handle);
}

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    int size_ip,n;
    struct sniff_ip *ip_header;
    struct sniff_tcp *tcp_header;
    struct sniff_udp *udp_header;
    char dest_ip[30];
    char source_ip[30];
    u_char ttl;
    double x;


    
    ip_header=(struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip=IP_HL(ip_header)*4;
    ttl = (ip_header->ip_ttl);
    if (size_ip < 20) 
    {
        fprintf(stderr,"   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    strcpy(dest_ip,inet_ntoa(ip_header->ip_dst));
    strcpy(source_ip,inet_ntoa(ip_header->ip_src));
    //tcp_header = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    if(strcmp(dest_ip,inet_ntoa(cli_addr.sin_addr)) == 0  )
    {
          //project
        /* packet has destination which is the victim */
        //tcp_header = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        // TODO : check for Ip protocol filed for TCP or UDP 

        if(ip_header->ip_p == IPPROTO_TCP)
        {
            tcp_header = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            if(ntohs(tcp_header->th_dport) == tcp_port)
                return;
            //else
              //  printf("Destination(packet): %s     Destination(client): %s     Source(packet): %s  DES_PORT: %d\n",dest_ip,inet_ntoa(cli_addr.sin_addr),source_ip,ntohs(tcp_header->th_dport));
        }
        if(ip_header->ip_p == IPPROTO_UDP)
        {
            udp_header = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
            if(ntohs(udp_header->udp_dport) == udp_port)
                return;
            //else
                //printf("Destination(packet): %s     Destination(client): %s     Source(packet): %s  DES_PORT: %d\n",dest_ip,inet_ntoa(cli_addr.sin_addr),source_ip,ntohs(udp_header->udp_dport));
        }
            // mark the packet and send it via udp_socket
            srand(time(0));
             x = drand48();
            // printf("x = %f",x);  //project
            if(x > prob)
            {
               // printf("Send the packet\n");
                // send packet over UDP port
                /* send attacker IP to endhost server */
                sprintf(udp_buffer,"%d",ttl);
                strcat(udp_buffer,",");
                strcat(udp_buffer,inet_ntoa(ip_header->ip_src));  
                if(flag_2 == 1)
                {
                    flag_2 =0;
                    router_log_2(udp_buffer);
                }        
               // printf("UDP BUFFER: %s\n",udp_buffer);

                n = sendto(udp_sockfd,udp_buffer,strlen(udp_buffer),0,(struct sockaddr*)&endhost_servaddr,sizeof(endhost_servaddr));
                if(n < 0)
                {  
                     perror("Sendto failed");
                     exit(1);
                }
                    router_log_3();
                    
                    //close(udp_sockfd);
        
            } 
            else
            {
                // nothing will happpen and the packet will go to the next router and again checked for marking
            } 
        
            
     }
}

void create_udp_socket()
{
    /* create a UDP socket */
    if((udp_sockfd = socket(AF_INET,SOCK_DGRAM,0)) < 0 )
    {
        perror("Error creating UDP socket");
        exit(1);
    }

    /* Get address of endhost */
            
    if((endhost_server = gethostbyname(inet_ntoa(cli_addr.sin_addr))) == NULL)     // 127.0.0.1
    {
        perror("No such host");
        exit(1);
    }

    bzero((char *)&endhost_servaddr,sizeof(endhost_servaddr));
    endhost_servaddr.sin_family = AF_INET;
    bcopy((char *)endhost_server->h_addr, (char *)&endhost_servaddr.sin_addr.s_addr, endhost_server->h_length);
    endhost_servaddr.sin_port=htons(udp_port);
    strcpy(udp_buffer,"Router replied back");
}





void handle_commandline(int argc, char  *argv[])
{
    int i;
    if(argc == 1)
    {
        fprintf(stdout,"Usage: router [-t port] [-u port] [-e epoch] [-p prob]\n");
        exit(1);
    }
    for(i=1;i<argc;i=i+2)
    {
        if(strcmp(argv[i],"-t")==0)
        {
            if(argv[i+1] == NULL || *argv[i+1] == '-' )
            {
                fprintf(stdout,"Usage: router [-t port] [-u port] [-e epoch] [-p prob]\n");
                exit(1);
            }
            tcp_port=atoi(argv[i+1]);
            continue;
        }

        if(strcmp(argv[i],"-u") == 0)
        {
            if(argv[i+1] == NULL || *argv[i+1] == '-' )
            {
                fprintf(stdout,"Usage: router [-t port] [-u port] [-e epoch] [-p prob]\n");
                exit(1);
            }
            udp_port=atoi(argv[i+1]);
            continue;
        }

        if(strcmp(argv[i],"-e") == 0)
        {
            if(argv[i+1] == NULL || *argv[i+1] == '-' )
            {
                fprintf(stdout,"Usage: router [-t port] [-u port] [-e epoch] [-p prob]\n");
                exit(1);
            }
            epoch = atoi(argv[i+1]);
            continue;
        }

        if(strcmp(argv[i],"-p") ==0)
        {
            if(argv[i+1] == NULL || *argv[i+1] == '-' )
            {
                fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
                exit(1);
            }
            prob = atof(argv[i+1]);
            continue;
        }
    }
}


void get_ip()
{
    getifaddrs(&addr);
    while(addr)
    {
        if(addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *paddr = (struct sockaddr_in *)addr->ifa_addr;
            
            if(strcmp("127.0.0.1",inet_ntoa(paddr->sin_addr)) == 0)
            {
                // skip
            }
            else
            {
                strcpy(my_ip,inet_ntoa(paddr->sin_addr));
                dev = addr->ifa_name;
                //fprintf(stdout,"MY IP:%s \n",my_ip);  //project
                break;  
            }
            
            
        }
        addr = addr->ifa_next;
    }
    
}

void router_log_1(char *endhost_ip)
{
    char filename[50];
    struct timeval current_time;

    if(gettimeofday(&current_time,NULL) != 0)
    {
        fprintf(stderr,"Error in gettimeofday(): %s\n",strerror(errno));
        exit(1);
    } 

    memset(filename,'\0',sizeof(filename));
    strcpy(filename,my_ip);
    strcat(filename,".router.log");
    if(fp_router_log == NULL)
    {
        fp_router_log = fopen(filename,"w+");
    }
    fprintf(fp_router_log,"%lu.%ld gotMarking %s   %s \n",current_time.tv_sec, current_time.tv_usec, inet_ntoa(cli_addr.sin_addr),tcp_buffer);

}

void router_log_2(char *udp_buffer)
{
    
    if(gettimeofday(&start_traceback_time,NULL) != 0)
    {
        fprintf(stderr,"Error in gettimeofday(): %s\n",strerror(errno));
        exit(1);
    } 
    //printf("First packet marked\n");  //project
    fprintf(fp_router_log,"%lu.%ld statedMarking    %s\n",start_traceback_time.tv_sec, start_traceback_time.tv_usec, udp_buffer);
   
}

void router_log_3()
{
    int sec_diff=0,usec_diff=0;
    struct timeval current_time;
    if(gettimeofday(&current_time,NULL) != 0)
    {
        fprintf(stderr,"Error in gettimeofday(): %s\n",strerror(errno));
        exit(1);
    } 
    sec_diff = current_time.tv_sec - start_traceback_time.tv_sec;
    usec_diff = current_time.tv_usec - start_traceback_time.tv_usec;
    if(sec_diff*1000000 + usec_diff <= epoch*1000000)
    {
        // do nothing
        no_of_traceback_packet++;
    }
    else
    {
        // its crossed epoch so print it and reset values
        fprintf(fp_router_log,"%ld.%lu     %s    %d\n",start_traceback_time.tv_sec,start_traceback_time.tv_usec,inet_ntoa(cli_addr.sin_addr),no_of_traceback_packet);
        no_of_traceback_packet = 0;
        start_traceback_time.tv_sec = start_traceback_time.tv_sec + epoch;
        no_of_traceback_packet++;
    }
}

void INT_handler(int signo)
{
    if(fp_router_log!=NULL)
    {
        fclose(fp_router_log);
    }
    exit(0);
}