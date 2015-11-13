/*
 * Project 4 Router.cpp 
 * CIS 457
 * 11/13/2015
 * Author(s):
 * Jonathan Powers, Kevin Anderson, Brett Greenman
 * Description:
 * This program recieves packets and knows if it is an ARP request and then sends an 
 * ethernet packet back. 
 */

#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <cstring>
#include <arpa/inet.h>
#include <string.h>
#include <iomanip>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>

int main(){
  int packet_socket;
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  char *interface, *src_ip, *dst_ip, *rec_ip, *target;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	printf("Creating Socket on interface %s\n",tmp->ifa_name);
	//create a packet socket
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket<0){
	  perror("socket");
	  return 2;
	}
	
	if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
	  perror("bind");
	}
      }
    }
  }
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  printf("Ready to recieve now\n");
  while(1){
    char buf[1500];
    struct sockaddr_ll recvaddr;
    socklen_t recvaddrlen=sizeof(struct sockaddr_ll);
    
    int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
    
    if(recvaddr.sll_pkttype==PACKET_OUTGOING){
      continue;
    }
    
      if ((((buf[12]) << 8) + buf[13]) == ETH_P_ARP){
		printf("Recieved ARP request\n");
	}	
      printf("Got packet from interface: %d, on router 1\n", recvaddr.sll_ifindex);
      printf("The length of the address is: %u\n", recvaddr.sll_halen);
      printf("Physical layer address (not in HEX) is: %u:%u:%u:%u:%u:%u\n\n", recvaddr.sll_addr[0], 
	recvaddr.sll_addr[1], recvaddr.sll_addr[2], recvaddr.sll_addr[3],
	recvaddr.sll_addr[4], recvaddr.sll_addr[5]);

	struct sockaddr_ll device = {0};	
  
	/*const unsigned char dst_mac[] = {
	recvaddr.sll_addr[0], recvaddr.sll_addr[1], recvaddr.sll_addr[2], recvaddr.sll_addr[3], recvaddr.sll_addr[4], recvaddr.sll_addr[5]};*/

	const unsigned char dst_mac[] = {0x56, 0xd7, 0x61, 0x4b, 0x6b, 0xc4};

	device.sll_family = AF_PACKET;
	device.sll_ifindex = recvaddr.sll_ifindex;
	device.sll_halen = recvaddr.sll_halen;
	device.sll_protocol = htons(ETH_P_ARP);
	memcpy(device.sll_addr, dst_mac, recvaddr.sll_halen);
	
	struct ether_arp requ;
	requ.arp_hrd = htons (ARPHRD_ETHER);
	requ.arp_pro = htons (ETH_P_IP);
	requ.arp_hln = ETHER_ADDR_LEN;
	requ.arp_pln = sizeof(in_addr_t);
	requ.arp_op = htons (ARPOP_REQUEST);
	memset(&requ.arp_tha, 0, sizeof(requ.arp_tha));

	const char* target = "10.1.0.3";
	struct in_addr target_addr = {0};
	if (!inet_aton(target,&target_addr)) {
    		printf("%s is not a valid IP address",target);
	}
	memcpy(&requ.arp_tpa,&target_addr.s_addr,sizeof(requ.arp_tpa));

	if (sendto(packet_socket,&requ,sizeof(requ),0,(struct sockaddr*)&device,sizeof(device)) < 0) {
    		printf("%s",strerror(errno));
	}
  }
  //exit
  return 0;
}
