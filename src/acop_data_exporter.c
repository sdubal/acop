/*
**     acopp_data_exporter.c - 
**
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <ipfix.h>
#include <mlog.h>

unsigned int acopp_ipfix_inilized = 0;
ipfix_t           *aIpFixHdr  = NULL;
ipfix_template_t  *aIpFixArpDataExp  = NULL;
ipfix_template_t  *aIpFixAlrmExp  = NULL;


int acopp_arp_data_template();
int acopp_arp_alrm_template();

int acopp_ipfix_init( int argc, char **argv )
{
    char      *optstr="hc:p:vstu";
    int       opt;
    char      chost[256];
    int       protocol = IPFIX_PROTO_TCP;
    int       sourceid = 12345;
    int       port     = IPFIX_PORTNO;
    int       verbose_level = 0;

    /* set default host */
    strcpy(chost, "localhost");

    /** process command line args
     */
    while( ( opt = getopt( argc, argv, optstr ) ) != EOF )
    {
	switch( opt )
	{
	  case 'p':
	    if ((port=atoi(optarg)) <0) {
		fprintf( stderr, "Invalid -p argument!\n" );
		exit(1);
	    }
            break;

	  case 'c':
            strcpy(chost, optarg);
	    break;

          case 's':
              protocol = IPFIX_PROTO_SCTP;
              break;

          case 't':
              protocol = IPFIX_PROTO_TCP;
              break;

          case 'u':
              protocol = IPFIX_PROTO_UDP;
              break;

          case 'v':
              verbose_level ++;
              break;

	  case 'h':
	  default:
              fprintf( stderr, "usage: %s [-hstuv] [-c collector] [-p portno]\n" 
                       "  -h               this help\n"
                       "  -c <collector>   collector address\n"
                       "  -p <portno>      collector port number (default=%d)\n"
                       "  -s               send data via SCTP\n"
                       "  -t               send data via TCP (default)\n"
                       "  -u               send data via UDP\n"
                       "  -v               increase verbose level\n\n",
                       argv[0], IPFIX_PORTNO  );
              exit(1);
	}
    }

    /** init loggin
     */
    mlog_set_vlevel( verbose_level );

    /** init lib 
     */
    if ( ipfix_init() <0) {
        fprintf( stderr, "cannot init ipfix module: %s\n", strerror(errno) );
        exit(1);
    }

    /** open ipfix exporter
     */
    if ( ipfix_open( &aIpFixHdr, sourceid, IPFIX_VERSION ) <0 ) {
        fprintf( stderr, "ipfix_open() failed: %s\n", strerror(errno) );
        exit(1);
    }

    /** set collector to use
     */
    if ( ipfix_add_collector( aIpFixHdr, chost, port, protocol ) <0 ) {
        fprintf( stderr, "ipfix_add_collector(%s,%d) failed: %s\n", 
                 chost, port, strerror(errno));
        exit(1);
    }



    //ADD templates 
    acopp_arp_data_template();
    acopp_arp_alrm_template();

    acopp_ipfix_inilized = 1; //L7_TRUE;
    
    return 0;
}

int acopp_ipfix_uninit()
{
    if (acopp_ipfix_inilized) {
        ipfix_delete_template(aIpFixHdr, aIpFixArpDataExp);
        ipfix_delete_template(aIpFixHdr, aIpFixAlrmExp);
        ipfix_close( aIpFixHdr );
        ipfix_cleanup();
    }

    return 0;
}


//ARP DATA TEMPLATE
int acopp_arp_data_template() 
{

    /** get template
     */
    if ( ipfix_new_data_template(aIpFixHdr, &aIpFixArpDataExp, 6 ) <0 ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }
    
    //ADD SRC and DST IP ADDR
    if ( (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                           0, IPFIX_FT_SOURCEIPV4ADDRESS, 4 ) <0 ) 
         || (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                              0, IPFIX_FT_SOURCEIPV4ADDRESS, 4 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    //ADD VLAN, DIRECTION
    if ( (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                           0, IPFIX_FT_VLANID, 2 ) <0 ) 
         || (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                              0, IPFIX_FT_FLOWDIRECTION, 2 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    //ADD PROTOCOL, PORT NUM
    if ( (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                           0, IPFIX_FT_PROTOCOLIDENTIFIER, 2 ) <0 ) 
         || (ipfix_add_field( aIpFixHdr, aIpFixArpDataExp, 
                              0, IPFIX_FT_PORTID, 2 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }


    return 0;
}


//ALARM TEMPLATE
int acopp_arp_alrm_template() 
{

    /** get template
     */
    if ( ipfix_new_data_template(aIpFixHdr, &aIpFixAlrmExp, 6 ) <0 ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }
    
    //ADD SRC and DST IP ADDR
    if ( (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                           0, IPFIX_FT_SOURCEIPV4ADDRESS, 4 ) <0 ) 
         || (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                              0, IPFIX_FT_SOURCEIPV4ADDRESS, 4 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    //ADD VLAN, PROTOCOL
    if ( (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                           0, IPFIX_FT_VLANID, 2 ) <0 )
        || (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                           0, IPFIX_FT_PROTOCOLIDENTIFIER, 2 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    //ADD PORT NUM
    if ( (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                           0, IPFIX_FT_PORTID, 2 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }


    //ADD INBOUND and OUTBOUND RATE
    if ( (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                           0, IPFIX_FT_INBOUND_RATE, 2 ) <0 ) 
         || (ipfix_add_field( aIpFixHdr, aIpFixAlrmExp, 
                              0, IPFIX_FT_OUTBOUND_RATE, 2 ) <0 ) ) {
        fprintf( stderr, "ipfix_new_template() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    return 0;
}

#if 0
int export_peer_node_arp_data(acPeerNode_t *peer_node)
{
    struct arp_data_export_s {
        uint32_t srcIp;
        uint32_t dstIp;
        uint16_t vlanId;
        uint16_t direction;
        uint16_t protocol;
        uint16_t portId;
    }__attribute__((packed))arpData;


    //lets update to local export data structure
    arpData.srcIp = peer_node->key.srcIp;  
    arpData.dstIp = peer_node->key.peerIp;
    arpData.vlanId = peer_node->key.vlanId;
    arpData.protocol = peer_node->key.protocol;
    arpData.drection = 0;  //Not updated in DB
    arpData.portId = peer_node->key.portId;

    /** export some data
     */
    printf( "\n\r Exporting peer node arp data ... " );
    fflush( stdout) ;

    if ( ipfix_export(aIpFixHdr, aIpFixArpDataExp, &arpData, sizeof(arpData)) <0 ) {
        fprintf( stderr, "ipfix_export() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    if ( ipfix_export_flush( aIpFixHdr ) <0 ) {
        fprintf( stderr, "ipfix_export_flush() failed: %s\n", 
                 strerror(errno) );
        exit(1);
    }

    printf( "ARP data exported.\n" );

    return 0;
}


#endif


