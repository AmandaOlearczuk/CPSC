#include <stdio.h>	//printf()
#include <string.h> //memset()
#include <sys/socket.h>	//socket
#include <stdlib.h> //exit();
#include <errno.h> //error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()

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
