#include <linux/if.h>
/* for make_promiscuos*/
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
/* for htons */
#include <arpa/inet.h>
#include <netinet/in.h>

/*for headers*/
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
/* include event */
// #include <event2/event.h>
/* for SIGINT*/
#include <signal.h>

#include "dbg.h"
#include "input.h"
#include "netwink.h"

#define ARRAY_SIZE(A) (sizeof(A) / sizeof(A[0]))

struct sock_filter filter_tcp_code[] = {
    {0x28, 0, 0, 0x0000000c}, {0x15, 0, 5, 0x000086dd},
    {0x30, 0, 0, 0x00000014}, {0x15, 6, 0, 0x00000006}, // select IP type tcp(6)
    {0x15, 0, 6, 0x0000002c}, {0x30, 0, 0, 0x00000036},
    {0x15, 3, 4, 0x00000006}, {0x15, 0, 3, 0x00000800},
    {0x30, 0, 0, 0x00000017}, {0x15, 0, 1, 0x00000006},
    {0x6, 0, 0, 0x00040000},  {0x6, 0, 0, 0x00000000}};

struct sock_filter filter_udp_code[] = {
    {0x28, 0, 0, 0x0000000c}, {0x15, 0, 5, 0x000086dd},
    {0x30, 0, 0, 0x00000014}, {0x15, 6, 0, 0x00000011}, // select udp(17) hex 11
    {0x15, 0, 6, 0x0000002c}, {0x30, 0, 0, 0x00000036},
    {0x15, 3, 4, 0x00000011}, {0x15, 0, 3, 0x00000800},
    {0x30, 0, 0, 0x00000017}, {0x15, 0, 1, 0x00000011},
    {0x6, 0, 0, 0x00040000},  {0x6, 0, 0, 0x00000000}};

struct sock_filter filter_icmp_code[] = {
    {0x28, 0, 0, 0x0000000c},
    {0x15, 0, 3, 0x00000800}, // select ethernet type 800(IP)
    {0x30, 0, 0, 0x00000017},
    {0x15, 0, 1, 0x00000001}, // select IP type, icmp(1)
    {0x6, 0, 0, 0x00040000},
    {0x6, 0, 0, 0x00000000}};

/* input*/
char *arguments[ARG_OPS];
int flags[NO_ARG_OPS];

/* output*/
char out_buffer[MAX_STR_OUTPUT] = {0};
int out_pipe[2];
int saved_stdout;

static volatile int pall_count = 0, pv_count = 0, piv_count = 0;
/* handle ctrl c*/
static volatile int keep = 1;

int dup_stdout();
void drop_buff();
void print_buff();

void handle_ethernet(const struct ether_header *ethernet_head) {
  printf("Destination Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
         ethernet_head->ether_dhost[0], ethernet_head->ether_dhost[1],
         ethernet_head->ether_dhost[2], ethernet_head->ether_dhost[3],
         ethernet_head->ether_dhost[4], ethernet_head->ether_dhost[5]);

  printf("Source Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
         ethernet_head->ether_shost[0], ethernet_head->ether_shost[1],
         ethernet_head->ether_shost[2], ethernet_head->ether_shost[3],
         ethernet_head->ether_shost[4], ethernet_head->ether_shost[5]);

  printf("Ethernet type: ");
  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_IP) {
    printf("IP\n");
  } else if (ntohs(ethernet_head->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(ethernet_head->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP\n");
  }
}

int handle_ip(const struct iphdr *ip_head) {
  char ipstr_s[INET_ADDRSTRLEN];
  char ipstr_d[INET_ADDRSTRLEN];
  if (ip_head->version != 4) {
    return ERROR_IPV6; // NOT SUPPORT IPv6
  }
  inet_ntop(AF_INET, &(ip_head->saddr), ipstr_s, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_head->daddr), ipstr_d, INET_ADDRSTRLEN);
  if (valid_argument(arguments[IP_NUM])) {
    if (!strcmp(arguments[IP_NUM], ipstr_s) ||
        !strcmp(arguments[IP_NUM], ipstr_d)) { /** filter match*/
      printf("Source IP: %s\n", ipstr_s);
      printf("Dest IP: %s\n", ipstr_d);
    } else {
      return ERROR_FILTER; /* filter not match*/
    }
  } else { /* no filter set*/
    printf("Source IP: %s\n", ipstr_s);
    printf("Dest IP: %s\n", ipstr_d);
  }

  return (ip_head->protocol);
  /*ICMP(1), TCP(6), UDP(17), PPTP(47)*/
}

int handle_tcp(const struct tcphdr *tcp_head) {
  uint16_t port_s = ntohs(tcp_head->source);
  uint16_t port_d = ntohs(tcp_head->dest);

  if (valid_argument(arguments[PORT_NUM])) {
    if (atoi(arguments[PORT_NUM]) == port_s ||
        atoi(arguments[PORT_NUM]) == port_d) {
      printf("Src port: %d, ", port_s);
      printf("Dest port: %d\n", port_d);
    } else {
      return ERROR_FILTER;
    }
  } else {
    printf("Src port: %d, ", port_s);
    printf("Dest port: %d\n", port_d);
  }
  printf("Seq: %u\n", ntohl(tcp_head->seq));
  printf("Ack seq: %u\n", ntohl(tcp_head->ack_seq));

  printf("Flag:");
  if (tcp_head->ack) {
    printf("[ACK]");
  }
  if (tcp_head->fin) {
    printf("[FIN]");
  }
  if (tcp_head->syn) {
    printf("[SYN]");
  }
  if (tcp_head->psh) {
    printf("[PSH]");
  }
  printf("\n");
  return 0;
}

int dup_stdout() {
  saved_stdout = dup(STDOUT_FILENO);

  if (pipe(out_pipe) != 0) {
    return ERROR_NORMAL;
  }
  dup2(out_pipe[1], STDOUT_FILENO);
  return close(out_pipe[1]);
}

void drop_buff() {
  // flush before opening stdout, so it actually cleared stdout???
  fflush(stdout);
}

void print_buff() {
  // dup2(saved_stdout, STDOUT_FILENO);
  // fflush(stdout);
  read(out_pipe[0], out_buffer,
       MAX_STR_OUTPUT); /* read from pipe into buffer */

  // todo save buffer in file..
  if (valid_argument(arguments[SAVE_NUM])) {
  }

  dup2(saved_stdout, STDOUT_FILENO); /* reconnect stdout for testing */
  printf("%s", out_buffer);
  fflush(stdout);
  memset(out_buffer, 0, sizeof(out_buffer));
}

char **get_all_interface(int *size) {

  char **interfaces;
  struct ifconf ifc;
  char buf[2048];
  int count = 0, i = 0;
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  check(sockfd != -1, "socket error");

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  int rc = ioctl(sockfd, SIOCGIFCONF, &ifc);
  check(rc != -1, "ioctl error");

  struct ifreq *it = ifc.ifc_req;
  count = ifc.ifc_len / sizeof(struct ifreq);

  /* alloc mem */
  interfaces = (char **)malloc(count * sizeof(char *));
  for (i = 0; i < count; ++i) {
    interfaces[i] = malloc(IFNAMSIZ * sizeof(char));
  }

  const struct ifreq *const end = it + count;
  for (i = 0; it != end; ++it) {
    if (ioctl(sockfd, SIOCGIFFLAGS, it) == 0) {
      if (!(it->ifr_flags & IFF_LOOPBACK)) { // don't count loopback
        if (ioctl(sockfd, SIOCGIFHWADDR, it) == 0) {
          interfaces[i] = it->ifr_name;
          ++i;
          log_d("interface name: %s\n", it->ifr_name);
        }
      }
    }
  }
  *size = i;

  close(sockfd);
  return interfaces;
error:
  return NULL;
}

int make_promiscuos(int sockfd, char *ethname) {
  // l2 set network card in promiscuos mode
  struct ifreq ethreq;
  strncpy(ethreq.ifr_name, ethname, IFNAMSIZ);
  int rc = ioctl(sockfd, SIOCGIFFLAGS, &ethreq);
  check(rc != -1, "ioctl error");

  ethreq.ifr_flags |= IFF_PROMISC;
  rc = ioctl(sockfd, SIOCSIFFLAGS, &ethreq);
  check(rc != -1, "ioctl2 error");
  return 0;

error:
  return -1;
}

int handle_promiscuos(int sockfd) {
  char **interfaces;
  int in_size = 0, rc = 0;
  /*获取所有在使用的网卡名称*/
  interfaces = get_all_interface(&in_size);
  check(interfaces != NULL, "interface error");
  for (int i = 0; i < in_size; ++i) {
    /* 设置网卡为兼容模式*/
    rc = make_promiscuos(sockfd, interfaces[i]);
    check(rc != -1, "promiscuos error");
  }
  free(interfaces);
  return 0;
error:
  return -1;
}

void intHandler(int dummy) {
  keep = 0;
  dup2(saved_stdout, STDOUT_FILENO); // open stdout
  printf("\n%d packets captured\n%d packets received by filter\n%d packets "
         "dropped by filter\n",
         pall_count, pv_count, piv_count);
  exit(1);
}

void sniffer(int listenfd, void **arg) {
  int n; /* number of Bytes received*/
  int err = 0;
  char buf[2048];
  const struct ether_header *ethernet_head;
  const struct iphdr *ip_head;
  const struct tcphdr *tcp_head;

  while (keep) {
    close(STDOUT_FILENO); /* close stdout, store in pipe*/
    n = recvfrom(listenfd, buf, sizeof(buf), 0, NULL, NULL);

    if (errno == EAGAIN || n <= 0) {
      continue; // ignore this
    }
    ++pall_count;
    /* check head Ethernet(14), IP(20), TCP(20)/UDP(8) , ICMP(8)*/
    printf("--------------\n");
    printf("%d bytes read\n", n);
    if (n < 42) {
      printf("Incomplete packet\n");
      ++piv_count;
      drop_buff();
      continue;
    }

    ethernet_head = (struct ether_header *)buf;
    handle_ethernet(ethernet_head);

    ip_head = (struct iphdr *)(buf + ETHERNET_HEADSIZE);
    int protocol = handle_ip(ip_head);
    // printf("protocol %d\n", protocol);
    if (protocol == ERROR_IPV6) {
      ++piv_count;
      printf("not support IPv6\n");
      drop_buff();
      continue;
    }
    if (protocol == ERROR_FILTER) {
      ++piv_count;
      printf("packet drroped by filter\n");
      drop_buff();
      continue; // drop
    }

    ++pv_count; // count as vaild packet

    switch (protocol) {
      {
      case TCP_P:
        printf("Layer-4 protocol %s\n", "TCP");
        // skip ip header;
        tcp_head = (struct tcphdr *)(buf + ETHERNET_HEADSIZE + IP_HEADSIZE);
        break;
      case UDP_P:
        printf("Layer-4 protocol %s\n", "UDP");
        print_buff();
        continue;
      case ICMP_P:
        printf("Layer-4 protocol %s\n", "ICMP");
        print_buff();
        continue;
      case PPTP_P:
        printf("Layer-4 protocol %s\n", "ICMP");
        print_buff();
        continue;
      default:
        printf("Layer-4 protocol %s\n", " UNKNOWN PROTOCOL");
        print_buff();
        continue;
      }
    }

    check(tcp_head, "error"); // here, tcpheader SHOULD not be NULL
    err = handle_tcp(tcp_head);
    if (err == ERROR_FILTER) {
      --pv_count;
      ++piv_count;
      printf("packet drroped by filter\n"); // this will never print to stdout
      drop_buff();
      continue;
    }
    // finally, print to stdout..
    print_buff();
  } // sniffer loop end
error:
  close(listenfd);
  exit(1);
}

int init_socket(int *sockfd) {
  char *protocal = arguments[PROTOCOL_NUM];
  char *ip = arguments[IP_NUM];
  char *port = arguments[PORT_NUM];

  *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); /*raw sockfd init*/

  /*set interface to promiscuos*/
  int rc = handle_promiscuos(*sockfd);
  if (rc == -1) {
    printf("can't make interface promiscuos\n");
    rc = 0;
  }

  // todo set ip / port in filter
  if (valid_argument(ip) || valid_argument(port) || valid_argument(protocal)) {
    if (valid_argument(ip)) {
      // filter = (struct sock_filter){0x15, 2, 0, 0x00001389};
      uint32_t ip_n = ipton(ip);
      if (ip_n == -1) {
        printf("invalid IP: \"%s\".\n", ip);
        goto error;
      }
      // filter_code[3] = (struct sock_filter){0x15, 2, 0, ip_n};
      // filter_code[5] = (struct sock_filter){0x15, 0, 12, ip_n};
    }
    if (valid_argument(port)) {
      uint32_t port_n = porton(port);
      if (port_n == -1) {
        printf("invalid port: %s\n", port);
        goto error;
      }
      // filter_code[14] = (struct sock_filter){0x15, 2, 0, port_n};
      // filter_code[16] = (struct sock_filter){0x15, 0, 1, port_n};
    }

    struct sock_fprog bpf;
    // bpf.filter = filter_code;
    if (valid_argument(protocal)) {
      if (!strcmp(protocal, "tcp")) {
        printf("tcp only\n");
        bpf.filter = filter_tcp_code;
        bpf.len = ARRAY_SIZE(filter_tcp_code);
      } else if (!strcmp(protocal, "udp")) {
        bpf.filter = filter_udp_code;
        bpf.len = ARRAY_SIZE(filter_udp_code);
      } else if (!strcmp(protocal, "icmp")) {
        bpf.filter = filter_icmp_code;
        bpf.len = ARRAY_SIZE(filter_icmp_code);
      }
    }
    /* set filter*/
    rc = setsockopt(*sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (rc == -1) {
      perror("can't set filter");
    }
  } else {
    log_d("no filter set");
  }

  if (*sockfd <= 0) {
    goto error; // don't use check() in inner func
  }
  return 0;
error:
  return -1;
}

/**
 * @brief netwink is a simple program like tcpdump(, but silly.
 * @author LeeReindeer
 * @usage
 * netwink [-f] [interface name] //restrict interface
        [-p] [port]//restrict port
        [-i] [IP address]// restrict IP
        [-t] [protocol name]//TCP/UDP/ICMP
        [-s] [out.txt] //save to file
        [-v] //check version
        [-h] //help
**/
int main(int argc, char *argv[]) {
  int rc = dup_stdout();
  check(rc != -1, "dup error");

  /* handle input start*/
  memset(flags, 0, sizeof(flags));
  for (int i = 0; i < 5; i++) {
    arguments[i] = malloc(sizeof(char) * MAX_STR_INPUT);
  }
  rc = handle_input(argc, argv, arguments, flags);
  if (rc == 1) {
    dup2(saved_stdout, STDOUT_FILENO);
    fflush(stdout);
    return 0;
  }
  check(rc != -1, "input error");
  /* handle input end*/

  int sockfd;

  rc = init_socket(&sockfd);
  check(rc != -1, "socket error");

  signal(SIGINT, intHandler);
  sniffer(sockfd, NULL);
  return 0;

error:
  dup2(saved_stdout, STDOUT_FILENO);
  exit(1);
}