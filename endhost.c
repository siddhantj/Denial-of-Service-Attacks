#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <errno.h>
#include "endhost.h"


/*global variables */
int tcp_port,udp_port;
char *router_file_path=NULL,*str=NULL,*tok=NULL;
int stop_thresh,stop_count=0;
socklen_t router_client_len;


int main(int argc,char *argv[])
{
	int sockfd_tcp,sockfd_udp,n;
	struct sockaddr_in router_serv_addr;	/* TCP client */
	//struct hostent *router_server;

	struct sockaddr_in endhost_serv_addr;	/* UDP server */
	struct sockaddr_in router_client_addr;	/* UDP client */

	char buffer[256],tcp_buffer[50],udp_buffer[50];
	char router_ip[50];
	FILE *fp=NULL;
	att_start = NULL;
	
	memset(buffer,'\0',sizeof(buffer));
	memset(router_ip,'\0',sizeof(router_ip));
	memset(tcp_buffer,'\0',sizeof(tcp_buffer));
	memset(udp_buffer,'\0',sizeof(udp_buffer));
	memset(filename,'\0',sizeof(filename));
	memset(my_ip,'\0',sizeof(my_ip));
	memset(hostname,'\0',sizeof(hostname));

	handle_commandline(argc,argv);

	/* find the ip address of the node to generate the filename */
	//get_ip();
	gethostname(hostname,1023);
	struct hostent *h;
	 h = gethostbyname(hostname);
	 strcpy(my_ip,h->h_name);
	 printf("%s ",my_ip);

	
	sprintf(filename,"%s.attackinfo",h->h_name);
	//check whether hostname.attackinfo file has been created 
	while((fp_attack_exist=fopen(filename,"r")) == NULL)
	{
		sleep(2);
	}
	//fprintf(stdout,"hostname.attackinfo file exists\n");	//project

	// read the file and send to ip addresses 
	if((fp=fopen(router_file_path,"r"))==NULL)
	{
		perror("Error opening file");
		exit(1);
	}

	
	// Creation of UDP socket- like a server 

	// call socket function 
	if((sockfd_udp = socket(AF_INET,SOCK_DGRAM,0)) < 0)
	{
		perror("Error creating UDP socket");
		exit(1);
	}
	// Initialize UDP socket 
	bzero((char *)&endhost_serv_addr,sizeof(endhost_serv_addr));
	endhost_serv_addr.sin_family = AF_INET;
	endhost_serv_addr.sin_addr.s_addr = INADDR_ANY;			//inet_addr(my_ip) ;	
    endhost_serv_addr.sin_port = htons(udp_port);

    //Bind socket 
    if (bind(sockfd_udp, (struct sockaddr *) &endhost_serv_addr,sizeof(endhost_serv_addr)) < 0)
    {
         perror("ERROR on binding");
         exit(1);
    } 
    


	/***************  TCP socket- like a client ****************/
	while(fgets(buffer,sizeof(buffer),fp) != NULL)
	{
		tok=strtok(buffer," \t");	// first call, pass the string 
		strcpy(router_ip,tok);
	
		// Create a socket 
		if((sockfd_tcp=socket(AF_INET, SOCK_STREAM,0)) < 0)
		{
			perror("Error creating TCP socket");
			exit(1);
		}
		
		/*if((router_server = gethostbyname(router_ip)) == NULL)	// router_ip 
		{
			//printf("%s\n",inet_ntoa((struct in_addr*) server.h_addr));
			perror("No such host");
			exit(1);
		} */
		bzero((struct sockaddr_in *)&router_serv_addr,sizeof(router_serv_addr));
		router_serv_addr.sin_family=AF_INET;
		router_serv_addr.sin_addr.s_addr = inet_addr(router_ip);
		//bcopy((char *)router_server->h_addr, (char *)&router_serv_addr.sin_addr.s_addr, router_server->h_length);
		router_serv_addr.sin_port = htons(tcp_port);

		// Connect to the router 
		if(connect(sockfd_tcp,(struct sockaddr*)&router_serv_addr,sizeof(router_serv_addr)) < 0)
		{
			perror("Error connecting 1");
			exit(1);
		}
																					//printf("Enter a message:");
																				//fgets(tcp_buffer,sizeof(tcp_buffer),stdin);
		strcpy(tcp_buffer,"SM");

		// Write message to the router 
		n = write(sockfd_tcp,tcp_buffer,sizeof(buffer));
		if ( n < 0)
		{
			perror("Error writing to socket ");
			//exit(1);
		}
		endhost_log(router_ip);
		
		close(sockfd_tcp);
		
	} 
	/*********************************************/
	 fclose(fp_endhost_log);
	   //sniff_endhost();
	/* SNIFFING CODE WILL BE INCLUDED HERE
	 * SNIFF THE PACKETS AND CHECK FOR IP ADDRESS,AS A UDP PACKET AND PORT NUMBER. IF IT MATCHES THE GIVEN PORT NUMBER THEN TAKE OUT THE ATTACKER IP FROM THE PAYLOAD
	 * AND PUT IT INTO LIST OF ATTACKER. ALSO FIND THE ROUTER IP AND ITS TTL AND PUT INTO ROUTER LIST BELONGING TO THAT PARTICULAR ATTACKER
	 * AFTER U HAVE RECEIVED THRESHOLD AMOUNT OF PACKETS ITS TIME TO STOP SNIFFING AND PRINT THE PATH ACCORDING TO INCREASING OR DECREASING 
	 * ORDER */

	 bzero((struct sockaddr_in *)&router_client_addr,sizeof(router_client_addr));
	 //fprintf(stdout,"Waiting for a response\n");	//project
	 router_client_len = sizeof(router_client_addr);
	for(;;)
	{
		
		n = recvfrom(sockfd_udp,udp_buffer,sizeof(udp_buffer),0,(struct sockaddr*)&router_client_addr,&router_client_len);
		memset(sender_ip,'\0',sizeof(sender_ip));
		//fprintf(stdout,"  Router IP: %s",inet_ntoa(router_client_addr.sin_addr));		//project
		strcpy(sender_ip,inet_ntoa(router_client_addr.sin_addr));
		if(n == 0)
		{
			fprintf(stderr,"Error in recvfrom()");
			exit(1);
		}
		//fprintf(stdout,"Message UDP recieved:%s\n ",udp_buffer);		//project
		stop_count++;		
		if(stop_count > stop_thresh)
		{
			start_path_reconstruction();
		}
		else
		{
			// append to the attacker linked list
			append_attack_list(udp_buffer);
		}

		
	} 

	

	return 0;
}

void handle_commandline(int argc,char *argv[])
{
	int i;
	if(argc == 1)
	{
		fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
		exit(1);
	}
	for(i=1;i<argc;i=i+2)
	{
		if(strcmp(argv[i],"-r")==0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-' )
			{
				fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
				exit(1);
			}
			router_file_path=argv[i+1];
			continue;
		}

		if(strcmp(argv[i],"-t") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-' )
			{
				fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
				exit(1);
			}
			tcp_port=atoi(argv[i+1]);
			continue;
		}

		if(strcmp(argv[i],"-u") == 0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-' )
			{
				fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
				exit(1);
			}
			udp_port=atoi(argv[i+1]);
			continue;
		}

		if(strcmp(argv[i],"-s") ==0)
		{
			if(argv[i+1] == NULL || *argv[i+1] == '-' )
			{
				fprintf(stdout,"Usage: endhost [-r filename] [-t port] [-u port] [-s stopthresh]\n");
				exit(1);
			}
			stop_thresh=atoi(argv[i+1]);
			continue;
		}
	}

}

void append_attack_list(char *buffer)	// void append_attack_list(char *buffer, char* sender_ip)
{
	char attacker_ip[30];
	int ttl;
	memset(attacker_ip,'\0',sizeof(attacker_ip));
	
	tok=strtok(buffer,",");
	ttl = atoi(tok);
	tok=strtok(NULL,",");
	strcpy(attacker_ip,tok);


	if(att_start == NULL)
	{
		att_start = (struct attacker_list*)malloc(sizeof(struct attacker_list));
		strcpy(att_start->attacker_ip,attacker_ip);
		att_start->next = NULL;
		att_start->list = NULL;
		if(att_start->list == NULL)
		{
			rt_start = (struct router_list*)malloc(sizeof(struct router_list));
			att_start->list = rt_start;
			strcpy(att_start->list->router_ip,sender_ip);
			att_start->list->ttl = ttl;
			att_start->list->next = NULL;
		}

	}
	else
	{
		att_ptr = att_start;
		while(att_ptr != NULL)
		{
			//printf("In while loop\n");
			att_prev_ptr = att_ptr;
			if(strcmp(att_ptr->attacker_ip,attacker_ip) ==  0)
			{
				// add new router into router_list else discart it
				rt_ptr = att_ptr->list;
				while(rt_ptr != NULL)
				{
					rt_prev_ptr = rt_ptr;
					if(strcmp(rt_ptr->router_ip,sender_ip) == 0)
					{
						//printf("Return");
						return; // router ip present in the list
					}
					rt_ptr = rt_ptr->next;
				}
				// add to router list 
				rt_new_ptr = (struct router_list*)malloc(sizeof(struct router_list));
				strcpy(rt_new_ptr->router_ip,sender_ip);
				rt_new_ptr->ttl = ttl;

				// do sorting here itself
				insert(att_ptr->list,rt_new_ptr);

				/*rt_prev_ptr->next = rt_new_ptr;
				rt_new_ptr->next = NULL; */
				//printf("Return");
				return;	//that atttacker is present and we added its new corresponding router_ip. So no need to go further
			}

			att_ptr = att_ptr->next;

		}
		//printf("out of while !!\n");
		// add a new attacker and hence a new list of router_ip
		att_new_ptr = (struct attacker_list*)malloc(sizeof(struct attacker_list));
		strcpy(att_new_ptr->attacker_ip, attacker_ip);
		att_prev_ptr->next = att_new_ptr;
		att_new_ptr->next = NULL;
		att_new_ptr->list = NULL;

		rt_new_ptr = (struct router_list*)malloc(sizeof(struct router_list));
		att_new_ptr->list = rt_new_ptr;
		strcpy(rt_new_ptr->router_ip,sender_ip);
		rt_new_ptr->ttl = ttl;
		rt_new_ptr->next = NULL;
	} 
		//fprintf(stdout,"Attacker IP:%s   TTL: %d",attacker_ip,ttl);

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
                //strcpy(filename,my_ip);
         
                //fprintf(stdout,"MY IP:%s \n",my_ip);	//project
                break;  
            }
            
            
        }
        addr = addr->ifa_next;
    }
    return;
    
}

void start_path_reconstruction()
{
	int dist=0;
	// after you are done with path reconstruction close the program
	fprintf(stdout,"Inside start_path reconstruction() and exit here\n");
	//att_start	
	/*att_ptr = att_start;
	while(att_ptr != NULL)
	{
		printf("Attacker: %s\n",att_ptr->attacker_ip);
		rt_ptr = att_ptr->list;
		while(rt_ptr != NULL)
		{
			printf("ROUTER IP: %s    TTL: %d\n",rt_ptr->router_ip,rt_ptr->ttl);
			rt_ptr = rt_ptr->next;

		}
		att_ptr = att_ptr->next;
	} */
		
	att_ptr = att_start;
	while(att_ptr != NULL)
	{
		printf("%s    ",my_ip);
		rt_ptr = att_ptr->list;
		dist=0;
		while(rt_ptr != NULL)
		{
			dist++;
			printf("%s ",rt_ptr->router_ip);
			printf("%d   ",dist);
			rt_ptr = rt_ptr->next;
		}	
		printf("%s\n",att_ptr->attacker_ip);
		att_ptr = att_ptr->next;
	}
	exit(0);
}

void endhost_log(char *router_ip)
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
	strcat(filename,".endhost.log");
	if(fp_endhost_log == NULL)
	{
		fp_endhost_log = fopen(filename,"w+");
	}
	fprintf(fp_endhost_log,"%lu.%ld	startMarking %s   SM \n",current_time.tv_sec, current_time.tv_usec, router_ip);
	
}

void insert(struct router_list *rt_start,struct router_list *rt_new_ptr)
{
	struct router_list *rt_ptr;
	rt_ptr = rt_start;
	// 3 conditions to insert: at start, at middle and at end
	while(rt_ptr != NULL)
	{
		if(rt_new_ptr->ttl < rt_ptr->ttl)	//when inserted at the beginning
		{
			rt_new_ptr->next = rt_ptr;
			rt_start = rt_new_ptr;
			att_ptr->list = rt_start;
			return;
		}
		if(rt_ptr->next != NULL)
		{
			if(rt_new_ptr->ttl > rt_ptr->ttl && rt_new_ptr->ttl < rt_ptr->next->ttl)	//when inserted at the middle of the loop
			{
				rt_new_ptr->next = rt_ptr->next;
				rt_ptr->next = rt_new_ptr;
				return;
			}	
		}
	

		if(rt_ptr->next == NULL && rt_new_ptr->ttl > rt_ptr->ttl)	//when inserting just at the end
		{
			rt_ptr->next = rt_new_ptr;
			rt_new_ptr->next = NULL;
			return;
		}	
		rt_ptr = rt_ptr->next;
	}
	
}