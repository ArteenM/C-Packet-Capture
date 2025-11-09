/* Standard C headers */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Networking headers */
#include <netinet/in.h>      /* sockaddr_in, IPPROTO_* */
#include <arpa/inet.h>      /* inet_ntoa, inet_addr */

/* Linux-specific raw packet capture headers */
#include <sys/ioctl.h>
#include <linux/if_packet.h> /* AF_PACKET, sockaddr_ll */
#include <net/if.h>          /* ifreq */
#include <netinet/if_ether.h> /* Ethernet headers */
#include <netinet/ip.h>     /* IP header struct */
#include <netinet/udp.h>    /* UDP header struct */
#include <netinet/tcp.h>    /* TCP header struct */

#include <getopt.h>
#include <errno.h>
#include <unistd.h>  /* for close() */


 // Helper macro to exit with an error

#define exit_with_error(msg) do {perror(msg); exit (EXIT_FAILURE);} while(0)

/*
 * packet_filter_transfer
 * A small structure intended to hold filtering/mapping information
 * for captured packets: transfer protocol (IP/UDP/TCP), source/dest
 * IPs and ports, interface names and MAC addresses.
 */
typedef struct {
    uint8_t transfer_protocol;   /* e.g. IPPROTO_TCP, IPPROTO_UDP */
    char * source_ip;            /* textual source IP (optional) */
    char * dest_ip;              /* textual dest IP (optional) */
    uint16_t source_port;        /* source port (host order) */
    uint16_t dest_port;          /* dest port (host order) */
    char *source_interface_name; /* name of source interface (e.g., "eth0") */
    char *dest_interface_name;   /* name of dest interface (if used)
                                   used to map an interface to a MAC */
    uint8_t source_mac[6];       /* binary MAC address (6 bytes) */
    uint8_t dest_mac[6];         /* binary dest MAC address */

} packet_filter_transfer;

/* Globals for storing parsed socket addresses (IPv4) */
struct sockaddr_in source_address, dest_address;

uint8_t filter_port(uint16_t source_port, uint16_t dest_port, packet_filter_transfer *filter) {
    if (filter->source_port != 0 && filter->source_port != source_port) {
        return 0; // Source port does not match
    }
    if (filter->dest_port != 0 && filter->dest_port != dest_port) {
        return 0; // Dest port does not match
    }
    return 1;
}

uint8_t filter_ip(packet_filter_transfer *filter) {
    if (filter->source_ip != NULL && strcmp(filter->source_ip, inet_ntoa(source_address.sin_addr)) != 0) {
        return 0; // Source IP does not match
    }
    if (filter->dest_ip != NULL && strcmp(filter->dest_ip, inet_ntoa(dest_address.sin_addr)) != 0) {
        return 0; // Dest IP does not match
    }
    return 1;
}

void log_eth_headers(struct ethhdr *eth, FILE *logfile) {
    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, "\t-Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "\t-Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, "\t-Protocol: %d\n", ntohs(eth->h_proto));
}

void log_ip_headers(struct iphdr *ip, FILE *lf) {
    fprintf(lf, "\nIP Header\n");
    
    fprintf(lf, "\t-Version : %d\n", (uint32_t)ip->version);
    fprintf(lf, "\t-Internet Header Length : %d bytes \n", (uint32_t)(ip->ihl * 4));
    fprintf(lf, "\t-Type of Service : %d\n", (uint32_t)ip->tos);
    fprintf(lf, "\t-Total Length : %d\n", ntohs(ip->tot_len));
    fprintf(lf, "\t-Identification : %d\n", (uint32_t)ip->id);
    fprintf(lf, "\t-Time to Live : %d\n", (uint32_t)ip->ttl);
    fprintf(lf, "\t-Protocol : %d\n", (uint32_t)ip->protocol);
    fprintf(lf, "\t-Header Checksum : %d\n", ntohs(ip->check));
    fprintf(lf, "\t-Source IP : %s\n", inet_ntoa(source_address.sin_addr));
    fprintf(lf, "\t-Destination : %s\n", inet_ntoa(dest_address.sin_addr));
}

void log_tcp_headers(struct tcphdr *tcp, FILE *lf) {
    fprintf(lf, "\nTCP Header\n");
    fprintf(lf, "\t-Source Port : %d\n", ntohs(tcp->source));
    fprintf(lf, "\t-Destination Port : %u\n", ntohs(tcp->dest));
    fprintf(lf, "\t-Sequence Number : %u\n", ntohl(tcp->seq));
    fprintf(lf, "\t-Acknowledgement Number : %d\n", ntohl(tcp->ack_seq));
    fprintf(lf, "\t-Header Length in Bytes : %d\n", (uint32_t)tcp->doff * 4);
    fprintf(lf, "\t ------- Flags ---------");
    fprintf(lf, "\t-Urgent Flag : %d\n", (uint32_t)tcp->urg);
    fprintf(lf, "\t-Acknowledgement Flag : %d\n", (uint32_t)tcp->ack);
    fprintf(lf, "\t-Push Flag : %d\n", (uint32_t)tcp->psh);
    fprintf(lf, "\t-Reset Flag : %d\n", (uint32_t)tcp->rst);
    fprintf(lf, "\t-Synchronise Flag : %d\n", (uint32_t)tcp->syn);
    fprintf(lf, "\t-Finish Flag : %d\n", (uint32_t)tcp->fin);
    fprintf(lf, "\t-Window Size : %d\n", ntohs(tcp->window));
    fprintf(lf, "\t-Checksum : %d\n", ntohs(tcp->check));
    fprintf(lf, "\t-Urgent pointer : %d\n", tcp->urg_ptr);
}

void log_udp_headers(struct udphdr *udp, FILE *lf) {
    fprintf(lf, "\nUDP Header\n");
    fprintf(lf, "\t-Source Port : %d\n", ntohs(udp->source));
    fprintf(lf, "\t-Destination Port : %u\n", ntohs(udp->dest));
    fprintf(lf, "\t-UDP Length : %u\n", ntohs(udp->len));
    fprintf(lf, "\t-UDP Checksum : %u\n", ntohs(udp->check));
}

void log_payload(uint8_t *buffer, int bufflen, int iphdrlen, uint8_t t_protocol, FILE *lf, struct tcphdr *tcp) {
    uint32_t t_protocol_header_size = sizeof(struct udphdr);
    if (t_protocol == IPPROTO_TCP) {
        t_protocol_header_size = (uint32_t)tcp->doff * 4;
    }
    uint8_t *packet_data = (buffer + sizeof(struct ethhdr) + iphdrlen + t_protocol_header_size);
    int remaining_data_size = bufflen - (sizeof(struct ethhdr) + iphdrlen + t_protocol_header_size);

    fprintf(lf, "\nData\n");
    for (int i = 0; i < remaining_data_size; i++) {
        if (i != 0 && i % 16 == 0) {
            fprintf(lf, "\n");
        }
        fprintf(lf, " %2.X ", packet_data[i]);
    }
    fprintf(lf, "\n");
}


void get_mac(char *if_name, packet_filter_transfer *filter, char *if_type) { // Takes interface name and type (source/dest)
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        exit_with_error("Socket creation failed for MAC retrieval");
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    if (strcmp(if_type, "source") == 0) {
        strcpy(filter->source_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
    else {
        strcpy(filter->dest_mac, (uint8_t *)ifr.ifr_hwaddr.sa_data);
    }

    memcpy(filter->source_mac, ifr.ifr_hwaddr.sa_data, 6);
}

// Utility Function to Compare Mac Addresses (first 6 bits)

uint8_t compare_mac(uint8_t *mac1, uint8_t *mac2) {
    for (uint8_t i = 0; i < 6; i++) {
        if (mac1[i] != mac2[i]) {
            return 0; // Not equal
        }
    }
    return 1; // Equal
}

void process_packet(uint8_t *buffer, int size, packet_filter_transfer *filter, FILE *logfile) {
    int ip_header_len;

    struct ethhdr *eth = (struct ethhdr *)buffer; // ethernet header

    if (ntohs(eth->h_proto) != 0x0800) {
        return; // Not an IP packet
    }

    if (filter->source_interface_name != NULL && compare_mac(filter->source_mac, eth->h_source) == 0) {
        return; // Source MAC does not match
    }

    if (filter->dest_interface_name != NULL && compare_mac(filter->dest_mac, eth->h_dest) == 0) {
        return; // Dest MAC does not match
    }

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr)); // IP header
    ip_header_len = ip->ihl * 4;

    memset(&source_address, 0, sizeof(source_address));
    memset(&dest_address, 0, sizeof(dest_address));
    source_address.sin_addr.s_addr = ip->saddr;
    dest_address.sin_addr.s_addr = ip->daddr;

    if(filter_ip(filter) == 0){
        return; // IP filter does not match
    }

    if (filter->transfer_protocol != 0 && ip->protocol != filter->transfer_protocol) {
        return; // Protocol does not match
    }

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    if(ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
        if (filter_port(ntohs(tcp->source), ntohs(tcp->dest), filter) == 0) {
            return; // Port filter does not match
        }
    }
    else if(ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);
        if (filter_port(ntohs(udp->source), ntohs(udp->dest), filter) == 0) {
            return; // Port filter does not match
        }
    }
    else {
        return; // Unsupported protocol
    }

    log_eth_headers(eth, logfile);
    log_ip_headers(ip, logfile);
    if (tcp != NULL) {
        log_tcp_headers(tcp, logfile);
    }
    if (udp != NULL) {
        log_udp_headers(udp, logfile);
    }

    log_payload(buffer, size, ip_header_len, ip->protocol, logfile, tcp);
}

int main(int argc, char **argv) {
    /*
     * Local variables used for option parsing and logging.
     * - c: for getopt
     * - log: small buffer for log messages
     * - logfile: optional FILE pointer if logging to a file
     */
    int c;
    char log[225];
    FILE *logfile = NULL;

    /* Initialize filter structure with zero/NULL defaults */
    packet_filter_transfer filter = {0, NULL, NULL, 0, 0, NULL, NULL};
    
    /* Generic socket address used later when receiving packets */
    struct sockaddr socket_address;

    /* Socket/file descriptors and length variables */
    int sockfd, source_address_len, buffer_len;

    /*
     * Allocate a large buffer to hold raw packet data. 65536 bytes is
     * a common choice to ensure a full packet (including headers) fits.
     */
    uint8_t *buffer = (uint8_t *) malloc(65536);

    /* Zero the buffer before use */
    memset(buffer, 0, 65536);

    /*
     * Create a raw packet socket bound to the device at the link layer.
     * AF_PACKET + SOCK_RAW allows receiving raw Ethernet frames. ETH_P_ALL
     * means we want packets for all Ethernet protocols (IP, ARP, etc.).
     */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        exit_with_error("Failed to create raw socket");
    }

    while (1) {
        static struct option long_options[] = {
            {"sip", required_argument, NULL, 's'}, // Source IP
            {"dip", required_argument, NULL, 'd'}, // Destination IP
            {"sport", required_argument, NULL, 'p'}, // Source port
            {"dport", required_argument, NULL, 'o'}, // Destination port
            {"sif", required_argument, NULL, 'i'}, // Source interface
            {"dif", required_argument, NULL, 'g'}, // Destination interface
            {"logfile", required_argument, NULL, 'f'}, // Log file
            {"tcp", no_argument, NULL, 't'}, // TCP protocol
            {"udp", no_argument, NULL, 'u'}, // UDP protocol
            {0, 0, 0, 0} // End of options
        };

        c = getopt_long(argc, argv, "tus:d:p:o:i:g:f:", long_options, NULL);

        if (c== -1) {
            break; // No more options
        }

        switch (c) {
            case 's':
                filter.source_ip = optarg;
                break;
            case 'd':
                filter.dest_ip = optarg;
                break;
            case 'p':
                filter.source_port = atoi(optarg);
                break;
            case 'o':
                filter.dest_port = atoi(optarg);
                break;
            case 'i':
                filter.source_interface_name = optarg;
                break;
            case 'g':
                filter.dest_interface_name = optarg;
                break;
            case 'f':
                strcpy(log, optarg);
                break;
            case 't':
                filter.transfer_protocol = IPPROTO_TCP;
                break;
            case 'u':
                filter.transfer_protocol = IPPROTO_UDP;
                break;
            default:
                abort();
        }
    }

    printf("t_protocol: %d\n", filter.transfer_protocol);
    printf("source_port %d\n", filter.source_port);
    printf("dest_port %d\n", filter.dest_port);
    printf("source_ip: %s\n", filter.source_ip);
    printf("dest_ip: %s\n", filter.dest_ip);
    printf("source interface %s\n", filter.source_interface_name);
    printf("dest interface %s\n", filter.dest_interface_name);
    printf("log file %s\n", log);

    if (strlen(log) == 0)
    {
        strcpy(log, "sniffer.txt");
    }
    logfile = fopen(log, "w");

    if (logfile == NULL) {
        exit_with_error("Failed to open log file");
    }

    if (filter.source_interface_name != NULL) {
        get_mac(filter.source_interface_name, &filter, "source");
    }

    if (filter.dest_interface_name != NULL) {
        get_mac(filter.dest_interface_name, &filter, "dest");
    }

    while (1) {
        source_address_len = sizeof(source_address);
        buffer_len = recvfrom(sockfd, buffer, 65536, 0,
                              &socket_address, (socklen_t *)&source_address_len);

        if (buffer_len < 0) {
            exit_with_error("Failed to receive packets");
        }

        process_packet(buffer, buffer_len, &filter, logfile);
        fflush(logfile);
        }
}