#include <stdio.h> //printf()
#include <string.h> //memset()
#include <sys/socket.h>	//socket
#include <stdlib.h> //exit();
#include <errno.h> //error number
#include <netinet/ip.h>	//iphdr struct
#include <netinet/tcp.h> //tcphdr struct
#include <arpa/inet.h> //inet_addr
#include <unistd.h> //sleep()

//Pseudo header is used in TCP checksum field calculation (along with TCP Header and TCP body)
struct pseudo_header
{
	unsigned int source_ip; //32bit
	unsigned int destination_ip; //32bit
	unsigned short tcp_segment_length; //16bit
	unsigned char protocol; //8bit
	unsigned char fixed_bits; //8bit
};

//Checksum calculator from Assignment's description page
unsigned short csum_tcp(unsigned short *buf, int nwords) {
	unsigned long sum = 0;
	sum += buf[6];
	sum += buf[7];
	sum += buf[8];
	sum += buf[9];
	sum += htons(6); // 6=TCP protocol in IP header
	sum += htons(20 + (nwords << 1)); // length of TCP header and payload
	
	for (int i = 10; i < 20 + nwords; ++i) {
		sum += buf[i];
	}
	
	while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

int main (void)
{
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if(s == -1)
	{
		perror("Socket creation failed");
		exit(1);
	}
	char datagram[4096];
 	char source_ip[32];
	
	memset(datagram, 0, sizeof(datagram)); //zero out datagram
	
	struct iphdr *ip_header = (struct iphdr *) datagram;
	struct tcphdr *tcp_header = (struct tcphdr *) (datagram + sizeof(struct iphdr));
	
	char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	
	//Define destination IPv4 address
	struct sockaddr_in ip4_dest_addr;
	ip4_dest_addr.sin_family = AF_INET;
	ip4_dest_addr.sin_port = htons(1203); 
	inet_pton(AF_INET, "136.159.5.25", &ip4_dest_addr.sin_addr);
	
	//Fill in ip header fields
	(*ip_header).version = 4; //Version
	(*ip_header).ihl = 5; //IHL
	(*ip_header).tos = 0; //Type of Service
	(*ip_header).tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	(*ip_header).id = htonl(12345); //Identification
	(*ip_header).frag_off = 0; //First fragment has offset 0
	(*ip_header).ttl = 128; 
	(*ip_header).protocol = IPPROTO_TCP;
	(*ip_header).check = csum_tcp((unsigned short *) datagram, (*ip_header).tot_len); //Checksum calculation
	//*ip_header.saddr = inet_addr(source_ip);
	inet_pton(AF_INET, "192.168.1.2", &(*ip_header).saddr); //fake source IP
	(*ip_header).daddr = ip4_dest_addr.sin_addr.s_addr; //Destination IP
	
	//Fill in the tcp header fields
	
	
	
	    
}
