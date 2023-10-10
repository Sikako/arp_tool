#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
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
#define ETH2_HEADER_LEN 14
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define HW_TYPE 1
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define ARP_SIZE 42 // ether header 14 + arp 28

// print detail 
#define DEBUG_MODE 1

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void get_usage();
void check_root();
void listen_mode(char *optarg, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip);
void query_mode(char *optarg, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip);
void spoof_mode(char **argv, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip);
int get_if_info(int *ifindex, uint8_t *mac, uint32_t *ip);
int bind_sockfd(int ifindex, int *sockfd);
int send_arp_request(int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t src_ip, uint32_t dst_ip);
int recv_arp_reply(int sockfd, uint8_t *buffer, uint8_t *target_mac_str);
int is_target_ip(uint8_t *buffer,  char *tgt_ip_addr);
int send_spoofing_packet(int sockfd, uint8_t *buffer);
int int_ip4(struct sockaddr *addr, uint32_t *ip);
int get_if_ip4(int sockfd, uint32_t *ip);
int format_ip4(struct sockaddr *addr, char *out);
void print_buffer(uint8_t *buffer);



int main(int argc, char **argv) {
	struct in_addr myip;
	const char *optstring = "hl:q:";	// options -abc
	int option;
	int sockfd;
	int ifindex;
	uint8_t src_mac[MAC_LENGTH];
	uint32_t src_ip;
	u_int8_t buffer[BUFFER_SIZE];
	
	// 1. First Check if User Use Root Priviledge
	check_root();


	if(argc < 2){
		get_usage();
		return 1;
	}

	// 取得網卡資訊
	if(get_if_info(&ifindex, src_mac, &src_ip)){
		perror("get_if_info");
		exit(-1);
	}

	// bind sockfd with interface
	if(bind_sockfd(ifindex, &sockfd)){
		perror("bind_sockfd");
		exit(-1);
	}

	// 2. Check options
	option = getopt(argc, argv, optstring);

	switch (option)
	{
	// -l listen mode
	case 'l':
		// printf("l, optarg: %s, optind: %d\n", optarg, optind);
		printf("### ARP sniffer mode ###\n");
		listen_mode(optarg, sockfd, buffer, ifindex, src_mac, &src_ip);
		break;
	
	// -q query mode
	case 'q':
		// printf("q, optarg: %s, optind: %d\n", optarg, optind);
		printf("### ARP query mode ###\n");
		query_mode(optarg, sockfd, buffer, ifindex, src_mac, &src_ip);
		break;

	case 'h':
		get_usage();
		break;

	default:
		if(argc == 3){
			printf("### ARP spoof mode ###\n");
			spoof_mode(argv, sockfd, buffer, ifindex, src_mac, &src_ip);
			break;
		}
		get_usage();
		break;
	}

	// Fill the parameters of the sa.
	
	return 0;
}

// Get useage
void get_usage(){
	printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
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
void listen_mode(char *optarg, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip){
	ssize_t data_size;
	char target_address[INET_ADDRSTRLEN], sender_address[INET_ADDRSTRLEN];
	bzero(buffer, BUFFER_SIZE);

	while(data_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL)){
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
		bzero(buffer, BUFFER_SIZE);
	}

}

// Function: Query packets with send()
void query_mode(char *optarg, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip){
	// 獲取網卡等需要的信息，定義在if.h中，配合ioctl()一起使用
	uint8_t tgt_mac_str[18];
	uint32_t dst_ip = inet_addr(optarg);
	bzero(buffer, BUFFER_SIZE);
	char *target_address = optarg;
	// printf("目標地址：%s\n", target_address);

	if(send_arp_request(sockfd, buffer, ifindex, src_mac, *src_ip, dst_ip)){
		perror("send_arp_request");
		exit(-1);
	}

	while(1) {
        int r = recv_arp_reply(sockfd, buffer, tgt_mac_str);
        if (r == 0) {
            printf("Mac address of %s is %s\n", target_address, tgt_mac_str);
            break;
        }
    }

}

// Function: Spoof mode
void spoof_mode(char **argv, int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t *src_ip){
	char *fake_mac_addr = argv[1];
	char *tgt_ip_addr = argv[2];
	bzero(buffer, BUFFER_SIZE);
	ssize_t data_size;

	if(DEBUG_MODE){
		printf("fake mac address: %s\n", fake_mac_addr);
		printf("target ip address: %s\n", tgt_ip_addr);
	}

	while(data_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL)){
		// printf("%d\n", 12 == 12);
		if(is_target_ip(buffer, tgt_ip_addr))
			printf("yes\n");
		else
			printf("no\n");
			// send_spoofing_packet(sockfd, buffer);
	}


}



int recv_arp_reply(int sockfd, uint8_t *buffer, uint8_t *target_mac_str){
	bzero(buffer, BUFFER_SIZE);
	ssize_t data_size;
	uint8_t tgt_mac[MAC_LENGTH];
	if((data_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL)) <= 0){
		perror("recvfrom");
		exit(-1);
	}
	struct ethhdr *rcv_pkt = (struct ethhdr *) buffer;
	struct ether_arp *arp_rply = (struct ether_arp *) (buffer + ETH2_HEADER_LEN);
	if(ntohs(rcv_pkt->h_proto) != ETH_P_ARP){
		perror("Not an ARP reply");
		exit(-1);
	}

	if(ntohs(arp_rply->ea_hdr.ar_op) != ARP_REPLY){
		perror("Not an ARP reply");
		exit(-1);
	}

	memcpy(tgt_mac, arp_rply->arp_sha, MAC_LENGTH);
	sprintf(target_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", tgt_mac[0], tgt_mac[1], tgt_mac[2], tgt_mac[3], tgt_mac[4], tgt_mac[5]);





	if(DEBUG_MODE){
		// printf("reply封包大小:%ld\n", data_size);
		printf("Reply 封包:\n");
		print_buffer(buffer);
	}

	
	return 0;
}

// send arp packet
int send_arp_request(int sockfd, uint8_t *buffer, int ifindex, uint8_t *src_mac, uint32_t src_ip, uint32_t dst_ip){
	bzero(buffer, BUFFER_SIZE);
	struct ethhdr *send_pkt = (struct ethhdr *) buffer;
	struct ether_arp *arp_req = (struct ether_arp *) (buffer + ETH2_HEADER_LEN); // arp 封包 位移6+6+2
	struct sockaddr_ll sa;
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex = ifindex;
	sa.sll_hatype = htons(ARPHRD_ETHER);
	sa.sll_halen = ETH_ALEN;
	// Broadcast
	memset(send_pkt->h_dest, 0xff, MAC_LENGTH);
	
	//Target MAC zero
    memset(arp_req->arp_tha, 0x00, MAC_LENGTH);

	//Set source mac to our MAC address
    memcpy(send_pkt->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->arp_sha, src_mac, MAC_LENGTH);
    memcpy(sa.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_pkt->h_proto = htons(ETH_P_ARP);

	/* Creating ARP request */
    arp_req->ea_hdr.ar_hrd = htons(HW_TYPE);
    arp_req->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_req->ea_hdr.ar_hln = MAC_LENGTH;
    arp_req->ea_hdr.ar_pln = IPV4_LENGTH;
    arp_req->ea_hdr.ar_op = htons(ARP_REQUEST);

	memcpy(arp_req->arp_spa, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->arp_tpa, &dst_ip, sizeof(uint32_t));

	if(sendto(sockfd, buffer, 42, 0, (struct sockaddr *)&sa, sizeof(sa)) == -1){
		perror("sendto");
		exit(-1);
	}

	printf("Request 封包:\n");
	print_buffer(buffer);
	return 0;

}

// 判斷是否buffer是目標ip
int is_target_ip(uint8_t *buffer,  char *tgt_ip_addr){
	struct ethhdr *send_pkt = (struct ethhdr *) buffer;
	struct ether_arp *arp_req = (struct ether_arp *) (buffer + ETH2_HEADER_LEN); // arp 封包 位移6+6+2
	char chk_ip[INET_ADDRSTRLEN];
	sprintf(chk_ip, "%d.%d.%d.%d", arp_req->arp_tpa[0], arp_req->arp_tpa[1], arp_req->arp_tpa[2], arp_req->arp_tpa[3]);
	printf("%s\n", chk_ip);
	
	if(strcmp(chk_ip, tgt_ip_addr) == 0)
		return 1;
	else
		return 0;
}

int send_spoofing_packet(int sockfd, uint8_t *buffer){

}

// 綁定sock --- if
int bind_sockfd(int ifindex, int *sockfd){
	if((*sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0){
		perror("open send socket error");
		exit(1);
	}

	struct sockaddr_ll sa;
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex = ifindex;
	// sa.sll_hatype = htons(ARPHRD_ETHER);
	// sa.sll_halen = ETH_ALEN;

	if(bind(*sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0){
		perror("bind");
		return 1;
	}

}

// 取得if資訊
int get_if_info(int *ifindex, uint8_t *mac, uint32_t *src){
	struct ifreq ifr;
	int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

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

// 從interface中取得ip address
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

void print_buffer(uint8_t *buffer){
	for(int i=0; i<60; i++){
		printf("%02X ", buffer[i]);
		if ((i+1) % 16 == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}