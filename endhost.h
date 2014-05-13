/* endhost.h
	Author: Siddhant Jawa
	Email: sjawa@usc.edu */

	#ifndef ENDHOST_H
	#define ENDHOST_H

	/* ethernet headers are always exactly 14 bytes [1] */


	char my_ip[30];
	struct ifaddrs *addr;
	FILE *fp_attack_exist=NULL;
	FILE *fp_endhost_log=NULL;
	char filename[50];
    char sender_ip[30];
    char hostname[50];


struct attacker_list
{
    char attacker_ip[30];
    struct router_list *list;
    struct attacker_list *next;
};

struct attacker_list *att_start,*att_ptr,*att_new_ptr,*att_prev_ptr;

struct router_list
{
    char router_ip[30];
    int ttl;
    struct router_list *next;
};
struct router_list *rt_start, *rt_ptr,*rt_new_ptr,*rt_prev_ptr;

	void handle_commandline(int argc,char *argv[]);
	void start_path_reconstruction(void);
	void endhost_log(char *ptr);
	void append_attack_list(char *);
    void endhost_log(char *);
	void get_ip(void);
    void insert(struct router_list *,struct router_list *);

	#endif 
