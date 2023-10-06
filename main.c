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
#define BUFFER_SIZE 61

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void check_root();
void listen_packets(int sockfd, char *optarg);

int main(int argc, char **argv) {
	int sockfd_recv = 0, sockfd_send = 0;

	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	const char *optstring = "hl:q";	// options -abc
	int option;
	
	// 1. First Check if User Use Root Priviledge
	check_root();

	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

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
		listen_packets(sockfd_recv, optarg);
		break;
	
	// -q query mode
	case 'q':
		// printf("q, optarg: %s, optind: %d\n", optarg, optind);
		printf("### ARP query mode ###\n");
		// arp_pkt.arp = 
		
		break;

	case 'h':
		printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
		break;

	default:
		printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
		break;
	}





	

	
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	
	

	
	// Fill the parameters of the sa.



	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	
	
	


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
void listen_packets(int sockfd, char *optarg){
	int data_size;
	u_int8_t buffer[BUFFER_SIZE];
	char target_address[INET_ADDRSTRLEN], sender_address[INET_ADDRSTRLEN];
	bzero(buffer, sizeof(buffer));

	while(data_size = recv(sockfd, buffer, sizeof(buffer), 0)){
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

