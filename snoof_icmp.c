#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethheader {
    unsigned char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    unsigned char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    unsigned short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void spoof_icmp_reply(struct ipheader* ip)
{
    const char buffer[1500];
    int ip_header_len = ip->iph_ihl * 4;

    // Step 1: Make a copy from the original packet 
    memset((char*)buffer, 0, 1500);
    memcpy((char*)buffer, ip, ntohs(ip->iph_len));
    struct ipheader  * newip  = (struct ipheader *) buffer;
    struct icmpheader * newicmp = (struct icmpheader *) ((u_char *)buffer + ip_header_len);

    // Step 4: Construct the IP header (no change for other fields)
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 50; // Rest the TTL field
    newip->iph_protocol = IPPROTO_ICMP;

    newicmp->icmp_type = 0;

    newicmp->icmp_chksum = 0;
    newicmp->icmp_chksum = in_cksum((unsigned short *)newicmp, ntohs(ip->iph_len) - ip_header_len);

    // Step 5: Send out the spoofed IP packet
    send_raw_ip_packet(newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* declare pointers to packet headers */
    const struct ethheader *eth;  /* The ethernet header [1] */
    const struct ipheader *ip;              /* The IP header */

    eth = (struct ethheader*)(packet);
    if (eth->ether_type != ntohs(0x0800)) return;  //not an IP packet
    //if (eth->ether_shost == ntohs(0x08002761a6da)) return;
    //printf ("  Eth Source: %s\n", &eth->ether_shost);

    ip = (struct ipheader*)(packet + SIZE_ETHERNET);
    int ip_header_len = ip->iph_ihl * 4;

    printf("---------------------------------------\n");
    printf("        From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("          To: %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol == IPPROTO_ICMP){
        printf("    Protocol: ICMP\n");
        spoof_icmp_reply(ip);
    }

}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] == icmp-echo";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);

    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}

