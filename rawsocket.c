#include <stdio.h>	//printf()
#include <string.h> //memset()
#include <sys/socket.h>	//socket
#include <stdlib.h> //exit();
#include <errno.h> //error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()

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
}
