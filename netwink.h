#ifndef _netwink_h
#define _netwink_h
/* include event */
// #include <event2/event.h>
/*for headers*/
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>

#define ETHERNET_HEADSIZE sizeof(struct ether_header)
#define IP_HEADSIZE sizeof(struct iphdr)
#define TCP_HEAFSIZE sizeof(struct tcphdr)
/*ICMP(1), TCP(6), UDP(17), PPTP(47)*/
#define ICMP_P 1
#define TCP_P 6
#define UDP_P 17
#define PPTP_P 47

/* error code start*/
#define ERROR_NORMAL -1
#define ERROR_FILTER -2
#define ERROR_IPV6 -6
/* error code end*/

// struct sock_filter filter_code[];

char **get_all_interface(int *size);

int make_promiscuos(int sockfd, char *ethname);

// todo
int make_unpromiscuos(int sockfd, char *ethname);

int handle_promiscuos(int sockfd);

// void ctrlc_cb(evutil_socket_t sig, short events, void *arg);
// void read_cb(evutil_socket_t sockfd, short events, void *arg);

void handle_ethernet(const struct ether_header *ethernet_head);
int handle_ip(const struct iphdr *ip_head);
int handle_tcp(const struct tcphdr *tcp_head);

int init_socket(int *sockfd);

#endif // __NETWINK_H__