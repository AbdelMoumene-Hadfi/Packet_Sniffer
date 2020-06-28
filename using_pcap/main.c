#include <stdio.h>
#include <errno.h>
#include "header.h"
#include <stdlib.h>
#include <pcap/pcap.h>
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
  printf("packet with length of [%d]\n",header->len);
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const char *payload;
  unsigned int size_ip,size_tcp;
  //
  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
  size_ip=IP_HL(ip)*4;
  if(size_ip<20) {
    printf(" Invalid IP header length : %u bytes\n",size_ip);
    return EXIT_FAILURE;
  }
  printf("FROM : %s\t",inet_ntoa(ip->ip_src));
  printf("TO : %s\n",inet_ntoa(ip->ip_dst));
  tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
  size_tcp=TCP_OFF(tcp)*4;
  if(size_tcp<20) {
    printf(" Invalid TCP header length : %u bytes\n",size_tcp);
    return EXIT_FAILURE;
  }
  printf("SRC PORT: %d\t",ntohs(tcp->tcp_sport));
  printf("DEST PORT : %d\n",ntohs(tcp->tcp_dport));
  payload = (unsigned char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
}
void usage() {
  printf("PacketSniffer is a  \n");
  printf("usage : ./sniffe [interface-name] \n");


}
int main(int *argc,char *argv[]) {
  /*
  if(argc<2) {
    printf("usage : ./sniffe [interface-name] \n");
    return 0;
  }
  char *dev=argv[1];
  printf("device ->  %s\n",dev);*/
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldev;
  int findall_ret=pcap_findalldevs(&alldev,errbuf);
  if(findall_ret==PCAP_ERROR) {
    perror(errbuf);
    return EXIT_FAILURE;
  }
  if(alldev==NULL) {
    printf("error : no device found\n");
    return 2;
  }
  int i=0;
  pcap_if_t *temp=alldev;
  printf("device found : \n");
  while(temp!=NULL){
    printf("%d -> %s ",i,temp->name);
    if(temp->description!=NULL) {
      printf(": Description -> %s.",temp->description);
    }
    printf("\n");
    i++;
    temp=temp->next;
  }
  printf("choose your dev ->");
  scanf("%d",&i);
  while(i!=0) {
    alldev=alldev->next;
    i--;
  }
  printf("%s\n",alldev->name);
  pcap_t *handle;
  handle = pcap_open_live(alldev->name, BUFSIZ, 1, 1000, errbuf);
  if(handle==NULL){
    perror(errbuf);
    return EXIT_FAILURE;
  }
  bpf_u_int32 mask,net ;
  if(pcap_lookupnet(alldev->name,&net,&mask,errbuf)==PCAP_ERROR) {
    perror(errbuf);
    return EXIT_FAILURE;
  }

  struct bpf_program fp;
  char filter_exp[] = "";
  if(pcap_compile(handle,&fp,filter_exp,0,net)==PCAP_ERROR) {
      pcap_perror(handle,"pcap_compile");
      return EXIT_FAILURE;
  }
  if(pcap_setfilter(handle,&fp)==PCAP_ERROR) {
      pcap_perror(handle,"pcap_setfilter");
      return EXIT_FAILURE;
  }

  pcap_loop(handle,10,got_packet,NULL);

  /*cleanup */
  pcap_freealldevs(alldev);
  pcap_close(handle);

  return EXIT_SUCCESS;
}
