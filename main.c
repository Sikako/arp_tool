#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "ens33"
#define BUFFER_SIZE 512

// print detail 
#define DEBUG_MODE 1

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void check_root();
void listen_mode(char *optarg);
void query_mode(int sockfd, char *optarg);
int int_ip4(struct sockaddr *addr, uint32_t *ip);
int get_if_ip4(int sockfd, uint32_t *ip);
int get_if_info(int sockfd, int *ifindex, uint8_t *mac, uint32_t *ip);

int main(int argc, char **argv) {
	int sockfd_recv = 0, sockfd_send = 0;

	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	const char *optstring = "hl:q:";	// options -abc
	int option;
	
	// 1. First Check if User Use Root Priviledge
	check_root();

	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}

	// 2. Check options
	option = getopt(argc, argv, optstring);

	switch (option)
	{
	// -l listen mode
	case 'l':
		// printf("l, optarg: %s, optind: %d\n", optarg, optind);
		printf("### ARP sniffer mode ###\n");
		listen_mode(optarg);
		break;
	
	// -q query mode
	case 'q':
		// printf("q, optarg: %s, optind: %d\n", optarg, optind);
		printf("### ARP query mode ###\n");
		query_mode(sockfd_send, optarg);
		
		break;

	case 'h':
		printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
		break;

	default:
		printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
		break;
	}

	// Fill the parameters of the sa.
	
	return 0;
}

// Function: Check if is executed with root priviledge
void check_root(){
	if (geteuid() != 0){
		printf("ERROR: You must be root to use this tool!");
		exit(1);
	}else{
		printf("[ ARP sniffer and spoof program ]\n");
	}
}


// Function: Listen packets with recv()
void listen_mode(char *optarg){
	int data_size;
	u_int8_t buffer[BUFFER_SIZE];
	char target_address[INET_ADDRSTRLEN], sender_address[INET_ADDRSTRLEN];
	bzero(buffer, sizeof(buffer));
	int sockfd_recv;

	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	while(data_size = recv(sockfd_recv, buffer, sizeof(buffer), 0)){
		sprintf(target_address, "%d.%d.%d.%d", buffer[38], buffer[39], buffer[40], buffer[41]);
		sprintf(sender_address, "%d.%d.%d.%d", buffer[28], buffer[29], buffer[30], buffer[31]);

		if (strcmp(optarg, "-a") == 0 || strcmp(optarg, target_address) == 0)
			printf("Get ARP packet - Who has %s?\t\t\tTell %s\n", target_address, sender_address);
		// printf("%d", packet.arp.ea_hdr.ar_hrd);

		// for(int i = 0; i < data_size; i++){
		// 	printf("%02X ", buffer[i]);
		// 	if ((i+1) % 16 == 0 && i != 0)
		// 		printf("\n");
		// }
		// printf("\n");

		// printf("192: %d\n",  buffer[44]);
		bzero(buffer, sizeof(buffer));
	}

}

// Function: Query packets with send()
void query_mode(int sockfd, char *optarg){
	#define ETH2_HEADER_LEN 14
	#define MAC_LENGTH 6
	// 獲取網卡等需要的信息，定義在if.h中，配合ioctl()一起使用
	u_int8_t buffer[BUFFER_SIZE];
	int ifindex;
	uint8_t mac[MAC_LENGTH];
	int src;
	uint32_t dst = inet_addr(optarg);

	struct ifreq ifr;
	struct ethhdr *send_pkt = (struct ethhdr *) buffer;
	struct ether_arp *arp_req = (struct ether_arp *) (buffer + ETH2_HEADER_LEN); // arp 封包 位移6+6+2
	
	char *target_address = optarg;
	printf("目標地址：%s\n", target_address);

	if(get_if_info(sockfd, &ifindex, mac, &src)){
		perror("get_if_info");
		exit(-1);
	}

	
	// build a struct arp packet

	// Broadcast
	memset(send_pkt->h_dest, 0xff, MAC_LENGTH);
	// memset(send_pkt->h_source, )

}

// 取得if資訊
int get_if_info(int sockfd, int *ifindex, uint8_t *mac, uint32_t *src){
	struct ifreq ifr;
		
	// 取網卡名
	memcpy(ifr.ifr_name, DEVICE_NAME, IF_NAMESIZE);

	// 獲取網卡索引
	if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1){
		perror("SIOCGIFINDEX");
		exit(-1);
	}
	*ifindex = ifr.ifr_ifindex;

	// 獲取網卡MAC
	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1){
		perror("SIOCGIFHWADDR");
		exit(-1);
	}

	uint8_t mac_str[18];
	memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);
	sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	// 獲取網卡IP
	if(get_if_ip4(sockfd, src)){
		perror("get_ip_ipr");
		exit(-1);
	}
	
	if(DEBUG_MODE){
		printf("網卡名：%s\n", ifr.ifr_name);
		printf("網卡索引為：%d\n", *ifindex);
		printf("MAC地址：%s\n", mac_str);
	}
	

	return 0;
}

int get_if_ip4(int sockfd, uint32_t *ip){
	struct ifreq ifr;

	memcpy(ifr.ifr_name, DEVICE_NAME, IF_NAMESIZE);
	if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
		perror("SIOCGIFADDR");
		exit(-1);
	}

	if(int_ip4(&ifr.ifr_addr, ip)){
		perror("int_ip4");
		exit(-1);
	}

	if(DEBUG_MODE){
		struct sockaddr_in *i = (struct sockaddr_in *)&ifr.ifr_addr;
		char *IP = inet_ntoa(i->sin_addr);
		printf("網卡IP地址:%s\n", IP);
	}
	return 0;
}

// 轉換sockaddr struct -> network bytes order uint32_t
int int_ip4(struct sockaddr *addr, uint32_t *ip){
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        perror("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}