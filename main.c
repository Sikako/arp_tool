#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
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
#define BUFFER_SIZE 65535

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void check_root();

int main(int argc, char **argv) {
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	const char *optstring = "l:q:";	// options -abc
	int option;
	
	// 1. First Check if User Use Root Priviledge
	check_root();

	// 2. Check options
	option = getopt(argc, argv, optstring);
	switch (option)
	{
	// -l listen mode
	case 'l':
		printf("l, optarg: %s, optind: %d\n", optarg, optind);
		break;
	
	// -q query mode
	case 'q':
		printf("q, optarg: %s, optind: %d\n", optarg, optind);
		break;
	default:
		printf("1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");
		break;
	}


	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	char buffer[BUFFER_SIZE];
	int data_size;
	// bzero(buffer, sizeof(buffer));
	struct sockaddr_in IP_from;
	int fromlen = sizeof(IP_from);


	while(data_size = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, (struct sockaddr *)&IP_from, (socklen_t *)&fromlen)){
		printf("len%d\n", fromlen);
		for(int i = 0; i < data_size; i++){
        	printf("%02X ", buffer[i]);
        	if (i % 15 == 0 && i != 0)
            	printf("\n");
    	}
		printf("\n");
		bzero(buffer, sizeof(buffer));
	}



	
	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
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
	/* check if user execute with root */
	if (geteuid() != 0){
		printf("ERROR: You must be root to use this tool!");
		exit(1);
	}
}
