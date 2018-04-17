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
char drop_buffer[MAX_STR_OUTPUT] = {0};
int out_pipe[2];
int saved_stdout;
FILE *fp = NULL;

static volatile int pall_count = 0, pv_count = 0, piv_count = 0;
/* handle ctrl c*/
static volatile int keep = 1;

int dup_stdout();
int open_stdout();
void drop_buff();
void print_buff();

void handle_ethernet(const struct ether_header *ethernet_head) {
  printff("Destination Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ethernet_head->ether_dhost[0], ethernet_head->ether_dhost[1],
          ethernet_head->ether_dhost[2], ethernet_head->ether_dhost[3],
          ethernet_head->ether_dhost[4], ethernet_head->ether_dhost[5]);

  printff("Source Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ethernet_head->ether_shost[0], ethernet_head->ether_shost[1],
          ethernet_head->ether_shost[2], ethernet_head->ether_shost[3],
          ethernet_head->ether_shost[4], ethernet_head->ether_shost[5]);

  printff("Ethernet type: ");
  if (ntohs(ethernet_head->ether_type) == ETHERTYPE_IP) {
    printff("IP\n");
  } else if (ntohs(ethernet_head->ether_type) == ETHERTYPE_ARP) {
    printff("ARP\n");
  } else if (ntohs(ethernet_head->ether_type) == ETHERTYPE_REVARP) {
    printff("Reverse ARP\n");
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
      printff("Source IP: %s\n", ipstr_s);
      printff("Dest IP: %s\n", ipstr_d);
    } else {
      return ERROR_FILTER; /* filter not match*/
    }
  } else { /* no filter set*/
    printff("Source IP: %s\n", ipstr_s);
    printff("Dest IP: %s\n", ipstr_d);
  }

  return (ip_head->protocol);
  /*ICMP(1), TCP(6), UDP(17), PPTP(47)*/
}

int handle_tcp(const struct tcphdr *tcp_head) {
  uint16_t port_s = ntohs(tcp_head->source);
  uint16_t port_d = ntohs(tcp_head->dest);

  if (valid_argument(arguments[PORT_NUM])) {
    uint16_t port_arg = porton(arguments[PORT_NUM]);
    if (port_arg == port_s || port_arg == port_d) {
      printff("Src port: %d, ", port_s);
      printff("Dest port: %d\n", port_d);
    } else {
      return ERROR_FILTER;
    }
  } else {
    printff("Src port: %d, ", port_s);
    printff("Dest port: %d\n", port_d);
  }
  printff("Seq: %u\n", ntohl(tcp_head->seq));
  printff("Ack seq: %u\n", ntohl(tcp_head->ack_seq));

  printff("Flag:");
  if (tcp_head->ack) {
    printff("[ACK]");
  }
  if (tcp_head->fin) {
    printff("[FIN]");
  }
  if (tcp_head->syn) {
    printff("[SYN]");
  }
  if (tcp_head->psh) {
    printff("[PSH]");
  }
  printff("\n");
  return ERROR_NONE;
}

/**
 * @brief  get all "up" interfaces
 * @param  *size: receiver to get the num of interfaces
 * @retval array of interfaces
 */
char **get_all_interface(int *size) {

  char **interfaces;
  struct ifconf ifc;
  char buf[2048];
  int count = 0, i = 0;
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  check(sockfd != ERROR_NORMAL, "socket error");

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  int rc = ioctl(sockfd, SIOCGIFCONF, &ifc);
  check(rc != ERROR_NORMAL, "ioctl error");

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

/**
 * @brief  make interface named as ethname promiscuos
 */
int make_promiscuos(int sockfd, char *ethname) {
  // l2 set network card in promiscuos mode
  struct ifreq ethreq;
  strncpy(ethreq.ifr_name, ethname, IFNAMSIZ);
  int rc = ioctl(sockfd, SIOCGIFFLAGS, &ethreq);
  check(rc != ERROR_NORMAL, "ioctl error");

  ethreq.ifr_flags |= IFF_PROMISC;
  rc = ioctl(sockfd, SIOCSIFFLAGS, &ethreq);
  check(rc != ERROR_NORMAL, "ioctl2 error");
  return 0;

error:
  return ERROR_NORMAL;
}

/**
 * @brief  call <code>get_all_interface()</code> and
 * <code>make_promiscuos</code> to make all interfaces promiscuos.
 */
int handle_promiscuos(int sockfd) {
  char **interfaces;
  int in_size = 0, rc = ERROR_NONE;
  /*获取所有在使用的网卡名称*/
  interfaces = get_all_interface(&in_size);
  check(interfaces != NULL, "interface error");
  for (int i = 0; i < in_size; ++i) {
    /* 设置网卡为兼容模式*/
    rc = make_promiscuos(sockfd, interfaces[i]);
    check(rc != ERROR_NORMAL, "promiscuos error");
  }
  free(interfaces);
  return ERROR_NONE;
error:
  return ERROR_NORMAL;
}

/**
 * @brief  handle SIGINT(CTRL + C), it print packets' statustucs then exit(1).
 */
void intHandler(int dummy) {
  keep = 0;
  open_stdout(); // open stdout
  printff("\n%d packets captured\n%d packets received by filter\n%d packets "
          "dropped by filter\n",
          pall_count, pv_count, piv_count);
  if (fp) {
    fclose(fp);
  }
  exit(1);
}

/**
 * @brief  redirect stdout to pipe
 */
int dup_stdout() {
  if (pipe(out_pipe) != 0) {
    exit(1);
  }
  return dup2(out_pipe[1], STDOUT_FILENO);
}

int open_stdout() { return dup2(saved_stdout, STDOUT_FILENO); }

void drop_buff() {
  close(out_pipe[1]);
  // flush before opening stdout, so it actually cleared stdout???
  fflush(stdout);
  read(out_pipe[0], out_buffer,
       MAX_STR_OUTPUT); /* read from pipe into buffer */
  if (strlen(drop_buffer) >= 1024) {
    memset(drop_buffer, 0, sizeof(drop_buffer));
  }
}

void save_file(char *buf) {
  int rc = 0;
  if (fp != NULL) {
    rc = fprintf(fp, "%s", buf);
    if (rc == -1) {
      log_e("cant't save to file.");
      fflush(stdout);
      exit(1);
    }
    fflush(fp);
  }
}

/**
 * @brief  read from pipe, and open stdout
 */
void print_buff() {
  close(out_pipe[1]);
  read(out_pipe[0], out_buffer,
       MAX_STR_OUTPUT); /* read from pipe into buffer */

  open_stdout(); /* reconnect stdout */
  printff("%s", out_buffer);
  save_file(out_buffer);

  memset(out_buffer, 0, sizeof(out_buffer));
}

/**
 * @brief  main loop,
 * call handle_ethernet, handle_ip and handle_tcp in sequence.
 * @param  listenfd: fd to recv packet
 * @param  **arg: this param is reserved.
 */
int sniffer(int listenfd, void **arg) {
  int n; /* number of Bytes received*/
  int err = ERROR_NONE;
  char buf[2048];
  const struct ether_header *ethernet_head;
  const struct iphdr *ip_head;
  const struct tcphdr *tcp_head;

  while (keep) {
    n = recvfrom(listenfd, buf, sizeof(buf), 0, NULL, NULL);

    if (errno == EAGAIN || n <= 0) {
      continue; // ignore this
    }
    dup_stdout(); // dup stdout to pipe
    ++pall_count;
    /* check head Ethernet(14), IP(20), TCP(20)/UDP(8) , ICMP(8)*/
    printff("--------------\n");
    printff("%d bytes read\n", n);
    if (n < 42) {
      printff("Incomplete packet\n");
      ++piv_count;
      drop_buff();
      continue;
    }

    ethernet_head = (struct ether_header *)buf;
    handle_ethernet(ethernet_head);

    ip_head = (struct iphdr *)(buf + ETHERNET_HEADSIZE);
    int protocol = handle_ip(ip_head);
    // printff("protocol %d\n", protocol);
    if (protocol == ERROR_IPV6) {
      ++piv_count;
      printff("not support IPv6\n");
      drop_buff();
      continue;
    }
    if (protocol == ERROR_FILTER) {
      ++piv_count;
      printff("packet drroped by filter\n");
      drop_buff();
      continue; // drop
    }

    ++pv_count; // count as vaild packet

    switch (protocol) {
      {
      case TCP_P:
        printff("Layer-4 protocol %s\n", "TCP");
        // skip ip header;
        tcp_head = (struct tcphdr *)(buf + ETHERNET_HEADSIZE + IP_HEADSIZE);
        break;
      case UDP_P:
        printff("Layer-4 protocol %s\n", "UDP");
        print_buff();
        continue;
      case ICMP_P:
        printff("Layer-4 protocol %s\n", "ICMP");
        print_buff();
        continue;
      case PPTP_P:
        printff("Layer-4 protocol %s\n", "ICMP");
        print_buff();
        continue;
      default:
        printff("Layer-4 protocol %s\n", " UNKNOWN PROTOCOL");
        print_buff();
        continue;
      }
    }

    check(tcp_head, "TCP error"); // here, tcpheader SHOULD not be NULL
    err = handle_tcp(tcp_head);
    if (err == ERROR_FILTER) {
      --pv_count;
      ++piv_count;
      printff("packet drroped by filter\n"); // this will never print to stdout
      drop_buff();
      continue;
    }
    // finally, print to stdout..
    print_buff();
  } // sniffer loop end
  return ERROR_NONE;
error:
  return ERROR_NORMAL;
}

/**
 * @brief  init sockfd with filter(use BPF pseudo machine code, protocol only)
 */
int init_socket(int *sockfd) {
  char *protocol = arguments[PROTOCOL_NUM];
  char *ip = arguments[IP_NUM];
  char *port = arguments[PORT_NUM];
  int rc = ERROR_NONE;

  *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); /*raw sockfd init*/
  if (*sockfd <= 0) {
    goto error; // don't use check() in inner func
  }

  if (valid_argument(ip) || valid_argument(port) || valid_argument(protocol)) {
    struct sock_fprog bpf;
    if (valid_argument(protocol)) {
      if (!strcmp(protocol, "tcp")) {
        printff("tcp only\n");
        bpf.filter = filter_tcp_code;
        bpf.len = ARRAY_SIZE(filter_tcp_code);
      } else if (!strcmp(protocol, "udp")) {
        bpf.filter = filter_udp_code;
        bpf.len = ARRAY_SIZE(filter_udp_code);
      } else if (!strcmp(protocol, "icmp")) {
        bpf.filter = filter_icmp_code;
        bpf.len = ARRAY_SIZE(filter_icmp_code);
      } else {
        return ERROR_ARG;
      }
      /* set filter*/
      rc = setsockopt(*sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
      if (rc == ERROR_NORMAL) {
        perror("can't set filter");
      }
    }
    if (valid_argument(ip)) {
      uint32_t ip_n = ipton(ip);
      if (ip_n == 1) {
        return ERROR_ARG_IP;
      }
    }
    if (valid_argument(port)) {

      uint16_t port_n = porton(port);
      if (port_n == 1) {
        return ERROR_ARG_PORT;
      }
    }
  } else {
    log_d("no filter set");
  }
  /*set interface to promiscuos*/
  rc = handle_promiscuos(*sockfd);
  if (rc == ERROR_NORMAL) {
    printff("can't make interface promiscuos\n");
  }
  return ERROR_NONE;
error:
  return ERROR_NORMAL;
}

int handle_main_input(int argc, char **argv) {
  /* handle input start*/
  int rc = 0;
  memset(flags, 0, sizeof(flags));
  // todo use calloc
  for (int i = 0; i < 5; i++) {
    arguments[i] = malloc(sizeof(char) * MAX_STR_INPUT);
  }
  rc = handle_input(argc, argv, arguments, flags);
  if (rc == 1) { /* case command: -v, -h, jus print and exit*/
    open_stdout();
    fflush(stdout);
    exit(0);
  }

  if (valid_argument(arguments[SAVE_NUM])) {
    fp = fopen(arguments[SAVE_NUM], "a");
    if (!fp) {
      return ERROR_NORMAL;
    }
  }
  return rc;
  /* handle input end*/
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
  int rc = handle_main_input(argc, argv);
  check(rc != ERROR_NORMAL, "argument error");

  saved_stdout = dup(STDOUT_FILENO);

  int sockfd;

  rc = init_socket(&sockfd);
  check(rc != ERROR_NORMAL, "socket error");
  check(rc != ERROR_ARG, "argument error");
  check(rc != ERROR_ARG_IP, "IP error");
  check(rc != ERROR_ARG_PORT, "port error");

  signal(SIGINT, intHandler);
  rc = sniffer(sockfd, NULL);
  return ERROR_NONE;

error:
  if (sockfd != ERROR_NORMAL) {
    close(sockfd);
  }
  if (fp) {
    fclose(fp);
  }
  open_stdout();
  exit(1);
}