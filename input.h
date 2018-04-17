#ifndef _input_h
#define _input_h

#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>

#define WINK_VERSION ("1.0-beta")

#define MAX_STR_INPUT 20
#define MAX_STR_OUTPUT (1024 * 2)
#define NO_ARG_OPS 2
#define ARG_OPS 5

#define INTERFACE_NUM 0
#define PORT_NUM 1
#define IP_NUM 2
#define PROTOCOL_NUM 3
#define SAVE_NUM 4

extern const char *short_opt;
extern struct option long_opt[];
extern char *help;

int handle_input(int argc, char *argv[], char *out[], int *flags);

int valid_argument(char *arg);

uint32_t ipton(char *ip4);
uint16_t porton(char *port);

void printff(const char *fmt, ...);

char *strlwr(char *in);

#endif // _input_h