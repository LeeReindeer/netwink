#include "input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *short_opt = "f:p:i:t:s:nlvh";
struct option long_opt[] = {{"interface", required_argument, NULL, 'f'},
                            {"port", required_argument, NULL, 'p'},
                            {"ip", required_argument, NULL, 'i'},
                            {"protocol", required_argument, NULL, 't'},
                            {"save", required_argument, NULL, 's'},
                            {"name", no_argument, NULL, 'n'},
                            {"local", no_argument, NULL, 'l'},
                            {"version", no_argument, NULL, 'v'},
                            {"help", no_argument, NULL, 'h'},
                            {NULL, 0, NULL, 0}};

/**
 * @brief  return itself with every char(word) to lower
 */
char *strlwr(char *in) {
  for (int i = 0; in[i] != '\0'; i++) {
    in[i] = tolower(in[i]);
  }
  return in;
}

/**
 * @brief valid argument is not NULL and not empty.
 */
int valid_argument(char *arg) { return (arg && strcmp(arg, "") != 0); }

/**
 * @brief valid IP(0-255) adnd return int vaule
 * @param  *ip4:
 * @retval on error: -1, else int of IP
 */
uint32_t ipton(char *ip4) {
  // int writer = 0;
  // for (int i = 0; ip4[i] != '\0'; i++) {
  //   if (ip4[i] != '.') {
  //     ip4[writer++] = ip4[i];
  //   }
  // }
  // ip4[writer] = '\0';
  int count = 0;
  while (ip4[count] != '\0') {
    count++;
  }
  // printf("count: %d\n", count);
  if (count < 7 || count > 12 + 3) { // 0.0.0.0
    return -1;
  }
  unsigned int ipbytes[4];
  int rc = sscanf(ip4, "%u.%u.%u.%u", &ipbytes[0], &ipbytes[1], &ipbytes[2],
                  &ipbytes[3]);
  if (rc == -1) {
    return -1;
  }
  for (int i = 0; i < 4; i++) {
    if (ipbytes[i] >= (1 << 8)) {
      return -1;
    }
  }
  return ipbytes[0] << 24 | ipbytes[1] << 16 | ipbytes[2] << 8 | ipbytes[3];
}

/**
 * @brief valid port(0-2^16-1)  and return int vaule
 * @param  *port:
 * @retval on error: -1, else int of port
 */
uint32_t porton(char *port) {
  uint32_t p = atoi(port);
  if (p > (1 << 16)) { // 2^16
    return -1;
  }
  return p;
}

/**
 * @brief handle user input
 * @param  argc:
 * @param  *argv[]:
 * @param  *out[]: receiver to get argument
 * @param  *flags: receiver to get no_argument flags
 */
int handle_input(int argc, char *argv[], char *out[], int *flags) {
  char c;
  // const char *short_opt = "f:p:i:t:s:nlvh";
  while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
    switch (c) {
    /*arg required start*/
    case 'f': // interface
      out[0] = strlwr(optarg);
      break;
    case 'p': // port
      out[1] = strlwr(optarg);
      break;
    case 'i': // IP
      out[2] = strlwr(optarg);
      break;
    case 't': // protocol
      out[3] = strlwr(optarg);
      break;
    case 's': // save file
      out[4] = strlwr(optarg);
      break;
    /*arg required end*/
    case 'n': // show host name
      flags[0] = 1;
      break;
    case 'l': // localhost
      flags[1] = 1;
      break;
    case 'v': // version
      flags[2] = 1;
      break;
    case 'h': // help
      flags[3] = 1;
      break;
    case '?':
      // TODO print hints
      return -1;
    default:
      break;
    }
  }
  return 0;
}