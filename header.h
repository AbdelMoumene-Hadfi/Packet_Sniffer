#include <netinet/in.h>
#define SIZE_ETHERNET 14
#define ETH_ADDR_LEN 6
/* Ethernet Header */
struct sniff_ethernet {
  unsigned char eth_dhost[ETH_ADDR_LEN];
  unsigned char eth_shost[ETH_ADDR_LEN];
  unsigned short eth_type;
};

/* Ip Header */
struct sniff_ip {
  unsigned char ip_vhl;
  unsigned char ip_tos;
  unsigned short ip_len;
  unsigned short ip_id;
  unsigned short ip_off;
  #define IP_RF 0x8000	   	/* reserved fragment flag */
	#define IP_DF 0x4000		  /* dont fragment flag */
	#define IP_MF 0x2000		  /* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  unsigned char ip_ttl;
  unsigned char ip_p;
  unsigned short ip_sum;
  struct in_addr ip_src,ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* Tcp Header*/
struct sniff_tcp {
  unsigned short tcp_sport;
  unsigned short tcp_dport;
  unsigned int   tcp_seq;
  unsigned int   tcp_ack;
  unsigned char  tcp_offrsvd;
  #define TCP_OFF(tcp) (((tcp)->tcp_offrsvd & 0xf0) >> 4)
  unsigned char  tcp_flags;
  #define TCP_FIN 0x01
	#define TCP_SYN 0x02
	#define TCP_RST 0x04
	#define TCP_PUSH 0x08
	#define TCP_ACK 0x10
	#define TCP_URG 0x20
	#define TCP_ECE 0x40
	#define TCP_CWR 0x80
	#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
  unsigned short tcp_win;
  unsigned short tcp_sum;
  unsigned short tcp_urp;
};
