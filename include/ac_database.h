/*
 * ac_database.h - DATABSE definitions
 *
 * author: Umesha G.M (ugm@cisco.com)
 */

#ifndef __AC_DATABASE_H__
#define __AC_DATABASE_H__

#include <time.h>
#include "ac_types.h"
#include "ac_app_defs.h"


#define AC_MAX_PORTS                24
#define AC_MAX_APPS                 AC_MAX_APP_INDEX
#define AC_MAX_PEER_ENTRIES         100
/*
 * Fixing the hsh table size to 255 only. Beyong this size needs re-modification of
 * hassh function defined in the ac_database.c file.
 * If proper hashing algo is used then max need is as many as (AC_MAX_PEER_ENTRIES)
 */
#define AC_MAX_PEER_TBL_HASH        55  


typedef struct acPeerTblKey_s {
    uchar8_t    portId;
    uint32_t    appId;
    uint32_t    vlanId;
    acIpAddr_t  srcIp;        //SRC IP for Tx, DST IP for Rx)
    acIpAddr_t  peerIp;
}__attribute__((packed))acPeerTblKey_t;


typedef struct acAppParsed_s {
    acPeerTblKey_t  key; //This should be the first one..
    uchar8_t        direction;
    uint32_t        pktSz;
 
}acAppParser_t;



//ARRAY BASED TABLE 
typedef struct acPortTbl_s {

    uint32_t            port;
    uint32_t            txPktCnt;
    uint32_t            rxPktCnt;
}acPortTbl_t;

//ARRAY BASED TABLE 
typedef struct acAppTbl_s {
    ushort16_t          appId;      //Protocol Id
    uint32_t            txPktCnt;
    uint32_t            rxPktCnt;

    uint32_t            txPktRate;
    uint32_t            rxPktRate;

    time_t              lastPktRcvdTime;
    time_t              lastTpkTxdTime;

}acAppTbl_t;


// HASH BASED TABLE : hash = port ^ AppId
typedef struct acPeerNode_s acPeerNode_t;
typedef struct acPortAppTbl_s {

    ushort16_t       port;          //Port Identifier 
    ushort16_t       appId;         //Protocol Identifier

    uint32_t         txPktCnt;
    uint32_t         rxPktCnt;

    uint32_t         txPktRate;
    uint32_t         rxPktRate;
    
    time_t          lastPktRcvdTime;
    time_t          lastTpkTxdTime;

    uint32_t         peersCnt;      //Number of PEERs using this protocol on particular port
    acPeerNode_t    *headp;         //Head node of the peer table entry of the port app table.
    acPeerNode_t    *tailp;         //Tail node of the peer table entry of the port app table.

}acPortAppTbl_t;

typedef union acAppProtData_u {

    acAppArpProtInfo_t  arp;
    
}acAppProtData_t;


struct acPeerNode_s {
    acPeerTblKey_t      key;
    //acIpAddr_t        peerIp;                   //TODO .. is it required to repeat key inf, may be not ?
    //acIpAddr_t        srcIp;                    //My own device interfaces IP

    acAppProtData_t     data;                    //e.g... acAppArpProtInfo_t
    acPeerNode_t        *nextp;                    //Next node in case of collisions.
    acPeerNode_t        *prevp;
};

// HASH BASED TABLE : hash = port ^ AppId
typedef struct acPeerTbl_s {

    acPeerNode_t    *headp;                    //Next node in case of collisions.
    acPeerNode_t    *tailp;                    //Is there a need for previous node of the same hash ...?
    acPortAppTbl_t  *portAppParent;           //Do we really need this field.. ?

}acPeerTbl_t;



/*=========================================================================
 * DATABASE APIs DECLARATIONS
 * =======================================================================*/


/* APIs */

void *acPeerTblEntryFind(acPeerTblKey_t *key);
void *acPeerTblEntryCreate(acPeerTblKey_t *key);
acReturn_t acPeerTblEntryDelete(acPeerTblKey_t *key);
void *acPeerTblEntryFindAndCreate(acPeerTblKey_t *key);


#endif //__AC_DATABASE_H__

