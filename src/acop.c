/***************************************************
 * * file:     testpcap1.c
 * * Date:     Thu Mar 08 17:14:36 MST 2001 
 * * Author:   Martin Casado
 * * Location: LAX Airport (hehe)
 * *
 * * Simple single packet capture program
 * *****************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include "../include/ac_database.h"

extern acReturn_t
acAppPktHandler(acPeerTblKey_t *pktInfoKey,  acAppParser_t *data);
char dev[20]; 
extern int acopp_ipfix_init(int, char **);

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

extern void send_dummy_export(void);

int main(int argc, char **argv)
{
    int i;
    uint16_t type = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    acAppParser_t pParser;

    u_char *ptr; /* printing out hardware header info */

    /* grab a device to peak into... */
    // dev = pcap_lookupdev(errbuf);
    printf("Total data  argc %d\n", argc);
    acopp_ipfix_init(argc, argv);
#if 0
    dev = argv[1];
    if (dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
#endif 
    
//    send_dummy_export();
    printf("DEV: %s\n",dev);

    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    
    /*
     * grab a packet from descr (yay!)                    
     * u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h) 
     * so just pass in the descriptor we got from         
     * our call to pcap_open_live and an allocated        
     * struct pcap_pkthdr                                 */
    while (1){
        packet = pcap_next(descr,&hdr);

        if(packet == NULL)
        {/* dinna work *sob* */
            printf("Didn't grab packet\n");
            exit(1);
        }

        /*  struct pcap_pkthdr {
         * struct timeval ts;   time stamp 
         *         bpf_u_int32 caplen;  length of portion present 
         *                 bpf_u_int32;         lebgth this packet (off wire) 
         *                         }
         *                                       */

        printf("Grabbed packet of length %d\n",hdr.len);
        printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 

        /* lets start with the ether header... */
        eptr = (struct ether_header *) packet;
        memset((void *)&pParser, 0, sizeof(pParser));
        if (hdr.len < 14){
            printf("Low len packet\n");
            continue;
        }

        /* Parse ASIC hdr, Update Port Details */
        pParser.key.portId = 0x00;

        /* Perform ethernet parsing */
        memcpy((void *)&pParser.dmac, packet, ETHER_ADDR_LEN);
        packet+=ETHER_ADDR_LEN;

        memcpy((void*)&pParser.smac, packet, ETHER_ADDR_LEN);
        packet+=ETHER_ADDR_LEN;
        /* copied from Steven's UNP */
        ptr = &pParser.dmac;
        i = ETHER_ADDR_LEN;
        printf(" Destination Address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");

        ptr = &pParser.smac ;
        i = ETHER_ADDR_LEN;
        printf(" Source Address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");

        /* Fetch outer vlan from ASIC header*/
         /* Skip all vlan tags */
          pParser.key.vlanId = 0x00; /* This needs to be fetched from ASIC hdr */
        type =  ntohs(*(uint16_t *) packet);   
        printf("Ethernet type hex:%x \n", type);
        pParser.key.portId = 0x00;
        while ((type == 0x8100) ||
                (type == 0x88a8)||
                (type == 0x9100)||
                (type == 0x9200)){
            printf("packet is vlan tagged\n");
            packet+=4;
            type =  ntohs(*(uint16_t *) packet);   
        }
            pParser.pktSz = hdr.len;

        switch(type){
            case ETHERTYPE_ARP:
                printf("Packet is ARP\n");
                pParser.key.appId = type;
                packet = packet +  2;  /* skip ETHER_TYPE */
                arp_hdr * arp = (arp_hdr *) packet;
                if (ntohs(arp->ptype) == ETH_P_IP){
                    printf("Packet is IPv4 ARP opcpode %d\n", 
                            ntohs(arp->opcode));
                    pParser.key.srcIp.type = 2;
                    pParser.key.srcIp.addr.v4addr = (uint32_t) arp->sender_ip;
                    pParser.key.peerIp.type = 2;
                    pParser.key.peerIp.addr.v4addr =  (uint32_t) arp->target_ip;
                }

                if (acAppPktHandler(&pParser.key, &pParser)){
                    printf("DB insert failed\n");
                }

                break;
            case 0x8035:
                pParser.key.appId = type;
                packet = packet +  2;  /* skip ETHER_TYPE */
                break;
            case ETHERTYPE_IP:
                pParser.key.appId = type;
                packet = packet +  2;  /* skip ETHER_TYPE */
                printf("Packet is IP\n");
                break;
             default:
                packet = packet +  2;  /* skip ETHER_TYPE */
                pParser.key.appId = type;
                break;
        }
        /* Do a couple of checks to see what packet type we have..*/
        if (type == ETHERTYPE_IP)
        {
            pParser.pktSz = hdr.len;
            if (acAppPktHandler(&pParser.key, &pParser)){
                printf("DB insert failed\n");
            }

        }else  if ((type == ETHERTYPE_ARP) || (type == 0x8035)){   /*ARP-RARP*/
            printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                    type, type);
            /* Parse ARP info */
            
        }
#if 0
   #endif        
        printf("\n");
    }
    return 0;
}
