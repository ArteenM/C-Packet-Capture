#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define exit_with_error(msg) do {packetError(msg)l exit (EXIT_FAILURE);} while(0)

typedef struct {
    uint8_t transfer_protocol;
    char * source_ip;
    char * dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    char *source_interface_name; 
    char *dest_interface_name; // Map interface to MAC address provided.
    uint8_t source_mac[6];
    uint8_t dest_mac[6];

} packet_filter_transfer;

struct sockaddr_in source_address, dest_address;

int main(int argc, char **argv) {
    int c;
    char log[225];
    FILE *logfile = NULL;
    packet_filter_transfer filter = {0, NULL, NULL, 0, 0, NULL, NULL};
    
    struct socket_address socket_address

    int sockfd, source_address_len, buffer_len;

    uint8_t *buffer = (uint8_t *) malloc(65536);

    memset(buffer, 0, 65536);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

}