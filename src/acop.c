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

int main(int argc, char **argv)
{
    int i;
    char *dev; 
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
    if (argc < 2){
        printf("You must enter input interface \n");
        return (0);
    }

    dev = argv[1];
    if (dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

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
        printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

        /* lets start with the ether header... */
        eptr = (struct ether_header *) packet;

        /* Do a couple of checks to see what packet type we have..*/
        if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
        {
            printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                    ntohs(eptr->ether_type),
                    ntohs(eptr->ether_type));
            pParser.key.portId = 0x00;
            pParser.key.appId = ntohs(eptr->ether_type);
            pParser.pktSz = hdr.len;
            if (acAppPktHandler(&pParser.key, &pParser)){
                printf("DB insert failed\n");
            }

        }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP){
            printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                    ntohs(eptr->ether_type),
                    ntohs(eptr->ether_type));
            pParser.key.portId = 0x00;
            pParser.key.appId = ntohs(eptr->ether_type);
            pParser.pktSz = hdr.len;
            if (acAppPktHandler(&pParser.key, &pParser)){
                printf("DB insert failed\n");
            }
        }

        /* copied from Steven's UNP */
        ptr = eptr->ether_dhost;
        i = ETHER_ADDR_LEN;
        printf(" Destination Address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");

        ptr = eptr->ether_shost;
        i = ETHER_ADDR_LEN;
        printf(" Source Address:  ");
        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");
    }
    return 0;
}
