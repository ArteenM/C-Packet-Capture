/* Standard C headers */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Networking headers */
#include <netinet/in.h>
#include <arpa/inet.h>

/* Linux raw packet headers */
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#define exit_with_error(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

/* ============================
   Packet filter configuration
   ============================ */

typedef struct {
    uint8_t transfer_protocol;
    char *source_ip;
    char *dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    char *source_interface_name;
    char *dest_interface_name;
    uint8_t source_mac[6];
    uint8_t dest_mac[6];
} packet_filter_transfer;

struct sockaddr_in source_address, dest_address;

/* ============================
   Traffic analysis structures
   ============================ */

#define MAX_IP_TRACK 1000

typedef struct {
    char ip[16];
    int count;
} ip_counter;

ip_counter ip_stats[MAX_IP_TRACK];
int ip_count = 0;

/* Packet statistics */
long total_packets = 0;
long tcp_packets = 0;
long udp_packets = 0;
long syn_packets = 0;

/* ============================
   Traffic analysis helpers
   ============================ */

void track_ip(char *ip)
{
    for(int i=0;i<ip_count;i++)
    {
        if(strcmp(ip_stats[i].ip, ip) == 0)
        {
            ip_stats[i].count++;
            return;
        }
    }

    if(ip_count < MAX_IP_TRACK)
    {
        strcpy(ip_stats[ip_count].ip, ip);
        ip_stats[ip_count].count = 1;
        ip_count++;
    }
}

void print_statistics()
{
    printf("\n===== Traffic Statistics =====\n");
    printf("Total Packets: %ld\n", total_packets);
    printf("TCP Packets: %ld\n", tcp_packets);
    printf("UDP Packets: %ld\n", udp_packets);
    printf("SYN Packets: %ld\n", syn_packets);

    printf("\nTop Talkers:\n");

    for(int i=0;i<ip_count && i<10;i++)
    {
        printf("%s : %d packets\n", ip_stats[i].ip, ip_stats[i].count);
    }

    if(syn_packets > 1000)
    {
        printf("\n[WARNING] Possible SYN Flood Detected\n");
    }
}

/* ============================
   Filtering
   ============================ */

uint8_t filter_port(uint16_t source_port, uint16_t dest_port, packet_filter_transfer *filter)
{
    if (filter->source_port != 0 && filter->source_port != source_port)
        return 0;

    if (filter->dest_port != 0 && filter->dest_port != dest_port)
        return 0;

    return 1;
}

uint8_t filter_ip(packet_filter_transfer *filter)
{
    if (filter->source_ip != NULL &&
        strcmp(filter->source_ip, inet_ntoa(source_address.sin_addr)) != 0)
        return 0;

    if (filter->dest_ip != NULL &&
        strcmp(filter->dest_ip, inet_ntoa(dest_address.sin_addr)) != 0)
        return 0;

    return 1;
}

/* ============================
   Logging helpers
   ============================ */

void log_eth_headers(struct ethhdr *eth, FILE *logfile)
{
    fprintf(logfile,"\nEthernet Header\n");

    fprintf(logfile,"Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            eth->h_source[0],eth->h_source[1],eth->h_source[2],
            eth->h_source[3],eth->h_source[4],eth->h_source[5]);

    fprintf(logfile,"Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],
            eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
}

void log_ip_headers(struct iphdr *ip, FILE *lf)
{
    fprintf(lf,"\nIP Header\n");
    fprintf(lf,"Source IP: %s\n", inet_ntoa(source_address.sin_addr));
    fprintf(lf,"Destination IP: %s\n", inet_ntoa(dest_address.sin_addr));
    fprintf(lf,"Protocol: %d\n", ip->protocol);
}

void log_tcp_headers(struct tcphdr *tcp, FILE *lf)
{
    fprintf(lf,"\nTCP Header\n");
    fprintf(lf,"Source Port: %d\n", ntohs(tcp->source));
    fprintf(lf,"Destination Port: %d\n", ntohs(tcp->dest));

    if(tcp->syn && !tcp->ack)
        syn_packets++;
}

void log_udp_headers(struct udphdr *udp, FILE *lf)
{
    fprintf(lf,"\nUDP Header\n");
    fprintf(lf,"Source Port: %d\n", ntohs(udp->source));
    fprintf(lf,"Destination Port: %d\n", ntohs(udp->dest));
}

/* ============================
   MAC utilities
   ============================ */

void get_mac(char *if_name, packet_filter_transfer *filter, char *if_type)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1)
        exit_with_error("Socket creation failed");

    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
        exit_with_error("MAC retrieval failed");

    close(fd);

    if(strcmp(if_type,"source")==0)
        memcpy(filter->source_mac, ifr.ifr_hwaddr.sa_data,6);
    else
        memcpy(filter->dest_mac, ifr.ifr_hwaddr.sa_data,6);
}

uint8_t compare_mac(uint8_t *mac1, uint8_t *mac2)
{
    for(int i=0;i<6;i++)
        if(mac1[i]!=mac2[i])
            return 0;

    return 1;
}

/* ============================
   Packet processing
   ============================ */

void process_packet(uint8_t *buffer,int size,packet_filter_transfer *filter,FILE *logfile)
{
    struct ethhdr *eth = (struct ethhdr*)buffer;

    if(ntohs(eth->h_proto)!=0x0800)
        return;

    struct iphdr *ip=(struct iphdr*)(buffer+sizeof(struct ethhdr));

    int ip_header_len = ip->ihl*4;

    source_address.sin_addr.s_addr=ip->saddr;
    dest_address.sin_addr.s_addr=ip->daddr;

    if(!filter_ip(filter))
        return;

    char *src = inet_ntoa(source_address.sin_addr);
    track_ip(src);

    total_packets++;

    struct tcphdr *tcp=NULL;
    struct udphdr *udp=NULL;

    if(ip->protocol==IPPROTO_TCP)
    {
        tcp_packets++;

        tcp=(struct tcphdr*)(buffer+sizeof(struct ethhdr)+ip_header_len);

        if(!filter_port(ntohs(tcp->source),ntohs(tcp->dest),filter))
            return;

        log_eth_headers(eth,logfile);
        log_ip_headers(ip,logfile);
        log_tcp_headers(tcp,logfile);
    }

    else if(ip->protocol==IPPROTO_UDP)
    {
        udp_packets++;

        udp=(struct udphdr*)(buffer+sizeof(struct ethhdr)+ip_header_len);

        if(!filter_port(ntohs(udp->source),ntohs(udp->dest),filter))
            return;

        log_eth_headers(eth,logfile);
        log_ip_headers(ip,logfile);
        log_udp_headers(udp,logfile);
    }
}

/* ============================
   Main
   ============================ */

int main(int argc,char **argv)
{
    int sockfd;
    int buffer_len;

    struct sockaddr socket_address;
    socklen_t socket_len = sizeof(socket_address);

    uint8_t *buffer = malloc(65536);

    if(!buffer)
        exit_with_error("malloc");

    packet_filter_transfer filter = {0,NULL,NULL,0,0,NULL,NULL,{0},{0}};

    sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    if(sockfd<0)
        exit_with_error("Raw socket failed");

    FILE *logfile = fopen("traffic.log","w");

    if(!logfile)
        exit_with_error("logfile");

    printf("Sniffer running...\n");

    while(1)
    {
        buffer_len = recvfrom(sockfd,buffer,65536,0,&socket_address,&socket_len);

        if(buffer_len < 0)
            exit_with_error("recvfrom");

        process_packet(buffer,buffer_len,&filter,logfile);

        if(total_packets % 5000 == 0)
            print_statistics();
    }

    close(sockfd);
}