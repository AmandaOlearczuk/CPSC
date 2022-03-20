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
	
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	
	    
}
