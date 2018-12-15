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
extern void send_dummy_export(void);

void hexDump (char *desc, void *addr, int len) 
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL){
        printf ("%s:\n", desc);
    }

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
}


typedef struct _arp_hdr arp_hdr;
struct __attribute__((__packed__)) _arp_hdr {
    uint16_t htype;
    uint16_t ar_pro;
    uint8_t hlen;
    uint8_t plen;
    uint16_t ar_op;
#if 0
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
#endif     
};


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
    arp_hdr *arp = NULL;
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
        /* ASIC hdr  processing */

        packet = packet+20;

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
        
        /* Skip 4 bytes of Platform Header */
         packet = packet + 4;

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

        hexDump("ARP packet", packet, sizeof(arp_hdr)+2);
        switch (type){
            case ETHERTYPE_ARP:
                printf("Packet is ARP\n");
                pParser.key.appId = type;
                packet = packet +  2;  /* skip ETHER_TYPE */

                arp = (arp_hdr *) packet;
                packet = packet + sizeof(arp_hdr);
                if (ntohs(arp->ar_pro) == ETH_P_IP){
                    printf("Packet is IPv4 ARP opcpode %d\n", 
                            ntohs(arp->ar_op));
                    /* Skip mac */
                    packet = packet + 6;
                    pParser.key.srcIp.type = 2;
                    pParser.key.srcIp.addr.v4addr = * (uint32_t*)packet;
                    packet = packet + 4;
                    packet = packet + 6;
                    printf("sender ip %x\n", pParser.key.srcIp.addr.v4addr);
                    pParser.key.peerIp.type = 2;
                    pParser.key.peerIp.addr.v4addr =  *(uint32_t *)packet;
                    printf("sender ip %x\n", pParser.key.peerIp.addr.v4addr);

                    i = 4;
                    ptr = &pParser.key.peerIp.addr.v4addr;
                    printf(" Destination IP Address:  ");
                    do{
                        printf("%s%d",(i == 4) ? " " : ".",*ptr++);
                    }while(--i>0);
                    printf("\n");

                    ptr =&pParser.key.srcIp.addr.v4addr;
                    i = 4;
                    printf(" Source Address:  ");
                    do{
                        printf("%s%d",(i == 4 ) ? " " : ".",*ptr++);
                    }while(--i>0);
                    printf("\n");

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
