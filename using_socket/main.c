/* general Header*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
/* Header  */
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
/* */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
/* */
#include <netinet/in.h>
#include <arpa/inet.h>
/* Header for network interface */
#include <net/if.h>
/* Header for  Ethernet */
#include <linux/if_ether.h>
/* */
#include <linux/filter.h>
#include <time.h>

/* */
#define PACKET_SIZE 1514
#define LOG_FILE "/tmp/l_tcpdump.log"
FILE *log;/* file fd*/

void time_now(time_t rawtime) {
  char time_buffer[80];
  struct tm *info;
  info=localtime(&rawtime);
  strftime(time_buffer,80,"%H:%M:%S",info);
  printf("at : %s \n",time_buffer);
  //fprintf(log,"%s :",time_now(rawtime));
}
void print_ethernet_hdr(struct ethhdr eth) {
  printf("Ethernet Header :\n");
  printf("\tSource. MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",eth.h_source[0],eth.h_source[1],eth.h_source[2],eth.h_source[3],eth.h_source[4],eth.h_source[5]);
  printf("\tDest.   MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],eth.h_dest[3],eth.h_dest[4],eth.h_dest[5]);
}
void print_ip_hdr(struct iphdr ip) {
  printf("IP Header : \n");
  printf("\tIPVersion      : %d\n",ip.version);
  printf("\tHeader Length  : %d\n",ip.ihl);
  printf("\tType of service: %ld\n",ip.tos);
  printf("\tTotal Length   : %ld Bytes\n",ntohs(ip.tot_len));
  printf("\tIdentification : %ld\n",ip.id);
  printf("\tTime to Live   : %ld\n",ip.ttl);
  printf("\tProtocol       : %ld\n",ip.protocol);
  printf("\tSource  IP     : %s\n",inet_ntoa(*(struct in_addr*)&ip.daddr));
  printf("\tDest.   IP     : %s\n",inet_ntoa(*(struct in_addr *)&ip.saddr));
}
void process_igmp_hdr(char *packet,int count_byte) {}
void process_icmp_hdr(struct icmphdr icmp) {
  printf("ICMP Header : \n");
  printf("\ttype    : %d (",icmp.type);
  switch(icmp.type) {
    case ICMP_ECHOREPLY	      :	 printf("Echo Reply)\n");break;
    case ICMP_DEST_UNREACH   	:	 printf("Destination Unreachable)\n");break;
    case ICMP_SOURCE_QUENCH	  :	 printf("Source Quench)\n");break;
    case ICMP_REDIRECT      	:	 printf("Redirect (change route) )\n");break;
    case ICMP_ECHO            :	 printf("Echo Request)\n");break;
    case ICMP_TIME_EXCEEDED	  :	 printf("Time Exceeded)\n");break;
    case ICMP_PARAMETERPROB	  :	 printf("Parameter Problem)\n");break;
    case ICMP_TIMESTAMP	      :	 printf("Timestamp Request)\n");break;
    case ICMP_TIMESTAMPREPLY	:	 printf("Timestamp Reply)\n");break;
    case ICMP_INFO_REQUEST	  :	 printf("Information Request)\n");break;
    case ICMP_INFO_REPLY	    :	 printf("Information Reply)\n");break;
    case ICMP_ADDRESS	        :  printf("Address Mask Request)\n");break;
    case ICMP_ADDRESSREPLY    :	 printf("Address Mask Reply)\n");break;
    default                   :  printf(")\n");break;
  }
  printf("\tCode    : %d\n",icmp.code);
  printf("\tCheck   : %ld\n",ntohs(icmp.checksum));
  if(icmp.type == 8) {
   printf("\tId        : %ld\n",ntohl(icmp.un.echo.id));
   printf("\tSequence  : %ld\n",ntohl(icmp.un.echo.sequence));
  }
  else {
    printf("\tGateway : %ld\n",ntohl(icmp.un.gateway));
  }
}
void process_udp_hdr(struct udphdr udp) {
  printf("UDP Header : \n");
  printf("\tSource  Port : %d\n",ntohs(udp.source));
  printf("\tDest.   Port : %d\n",ntohs(udp.dest));
  printf("\tLength  : %d\n",ntohs(udp.len));
  printf("\tCheck   : %d\n",ntohs(udp.check));
}
void process_tcp_hdr(struct tcphdr tcp) {
  printf("TCP Header : \n");
  printf("\tSource  Port : %ld\n",ntohs(tcp.source));
  printf("\tDest.   Port : %ld\n",ntohs(tcp.dest));
  printf("\tSeq.    : %ld\n",ntohl(tcp.seq));
  printf("\tAck.    : %ld\n",ntohl(tcp.ack_seq));
  printf("\tHeader Length: %d\n",tcp.doff);
  printf("\tURG     : %d\n",tcp.urg);
  printf("\tACK     : %d\n",tcp.ack);
  printf("\tPSH     : %d\n",tcp.psh);
  printf("\tRST     : %d\n",tcp.rst);
  printf("\tSYN     : %d\n",tcp.syn);
  printf("\tFIN     : %d\n",tcp.fin);
  printf("\tWindow  : %ld\n",ntohs(tcp.window));
  printf("\tCheck   : %ld\n",ntohs(tcp.check));
  printf("\tUrgent Ptr.  : %ld\n",ntohs(tcp.urg_ptr));
}
void process_packet(char *packet,int count_byte,time_t rawtime) {
  struct ethhdr eth;
  struct iphdr ip;
  memcpy(&eth,packet,sizeof(ETH_HLEN));
  memcpy(&ip,packet+ETH_HLEN,sizeof(struct iphdr));
  time_now(rawtime);
  print_ethernet_hdr(eth);
  print_ip_hdr(ip);
  if(ip.version ==4) {
      switch (ip.protocol) {
        case IPPROTO_ICMP : {
          struct icmphdr icmp;
          memcpy(&icmp,packet+ETH_HLEN+ ip.ihl*4,sizeof(struct icmphdr));
          process_icmp_hdr(icmp);
          break;
        }
        case IPPROTO_IGMP : {

          process_igmp_hdr(&packet,count_byte);
          break;
        }
        case IPPROTO_UDP  : {
          struct udphdr udp;
          memcpy(&udp,packet+ETH_HLEN+ ip.ihl*4,sizeof(struct udphdr));
          process_udp_hdr(udp);
          break;
        }
        case IPPROTO_TCP : {
          /*struct tcphdr tcp;
          memcpy(&tcp,packet+ETH_HLEN+ ip.ihl*4,sizeof(struct tcphdr));
          process_tcp_hdr(tcp);*/
          break;
        }
        default :
          printf(" : protocol %d\n", ip.protocol);
          //fprintf(log," : protocol %d", ip.protocol);
          break;
      }
      printf(" length : %d\n",count_byte);
      printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
      //fprintf(log,"\n");
  }
}
int main(int argc,char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s interface_name\n", argv[0]);
    exit(1);
  }
  /* */
  int s_fd;/* socket fd*/
  char if_name[IFNAMSIZ];/* interface name*/
  char packet[PACKET_SIZE+1];/* recieved packet */
  struct sockaddr_ll sock_addr;
  int count_byte;/* received bytes*/
  int count_packet = 0;/* received packet*/
  time_t rawtime;
  /* */
  /* BPF filter: tcpdump -ni wlo1 -s0 -dd ether dst ff:ff:ff:ff:ff:ff */
  struct sock_filter filter[] = {
    { 0x20, 0, 0, 0x00000002 },
    { 0x15, 0, 3, 0xffffffff },
    { 0x28, 0, 0, 0x00000000 },
    { 0x15, 0, 1, 0x0000ffff },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
   };
   struct sock_fprog sockf = {
     .filter = filter,
     .len = 6
   };

  /*
    Open a Raw socket
    AF_PACKET : for low-level packet interface
    ETH_P_ALL : to receive all protocols
   */
  if((s_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0) {
    fprintf(stderr,"unable to open a raw socket (%m)\n");
    exit(1);
  }
  /* Bind the socket to interface */
  memset(&sock_addr,0,sizeof(struct sockaddr_ll));
  sock_addr.sll_family = AF_PACKET;
  sock_addr.sll_protocol = htons(ETH_P_ALL); ;
  strncpy(if_name,argv[1],IFNAMSIZ);
  if_name[IFNAMSIZ-1]='\0';
  if((sock_addr.sll_ifindex = if_nametoindex(if_name)) ==0) {
    fprintf(stderr,"unknown interface %s\n",if_name);
    exit(1);
  }
  if(bind(s_fd,(struct sockaddr*)&sock_addr,sizeof(sock_addr))<0) {
    fprintf(stderr,"unable to listen to %s (%m)\n",if_name);
    exit(1);
  }
  /*
    Setup a filter
    SOL_SOCKET : socket api level

  if(setsockopt(s_fd,SOL_SOCKET,SO_ATTACH_FILTER,&sockf,sizeof(sockf))<0) {
    fprintf(stderr,"unable to set filter (%m)\n");
    exit(1);
  }*/
  /* */
  if((log = fopen(LOG_FILE,"a+"))==NULL) {
    fprintf(stderr,"unable to open %s (%m)\n",LOG_FILE);
    exit(1);
  }
  /* */
  while(1) {
    fflush(stdout);
    if((count_byte = recv(s_fd,packet,PACKET_SIZE,0))<0) {
      fprintf(stderr,"error while receving (%m)\n");
      exit(1);
    }
    /*
      ETH_HLEN : Total octets in ethernet header.
    */
    if(count_byte<ETH_HLEN+sizeof(struct iphdr)) {
      continue ;
    }
    time(&rawtime);
    count_packet++;
    process_packet(packet,count_byte,rawtime);
  }
  printf("%d : Packet recevied\n",count_packet);
  fprintf(log,"%d : Packet recevied\n",count_packet);
  fclose(log);
  close(s_fd);
  return 0 ;
}
