
/*file: ac_app_handlers.c
 *
 * This file defines the control protocol specific handlers for Adaptive CoPP module
 *
 * Notes: 
 *
 * Author: Umesha G.M (ugm@cisco.com)
 */
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ac_database.h"
#include "../include/ac_app_defs.h"
#include "../include/ac_app_api.h"


acAppHandlers_t appProtoHandlers[] =
{
    { AC_APP_ARP_INDEX, AC_APP_ARP_ID, acAppArpPktHandler},
    { AC_APP_ICMP_INDEX, AC_APP_ICMP_ID, NULL},


    //HEY...! do not add any handlers below this line. LAST One...
    { AC_MAX_APP_INDEX, 0x000, NULL} //This should be the last one.
};


    
/* 
 * @acAppArpPktHandler
 *
 * Entry function to handle the ARP protocol analytics
 *
 * Notes: 
 */
acReturn_t
acAppArpPktHandler (acPeerNode_t *peerNode, acAppParser_t *parser_data)
{
    /*todo arp data should be of paticular format. */
    acAppParser_t       *app = parser_data;    /* This will be filled by parser of the papplication packet. */
    acAppArpProtInfo_t  *arpInfo = &peerNode->data.arp;
    time_t               time;
    uint32_t             delta;

    if (!peerNode || !parser_data) {
        printf ("peer info is NULL %p or parser_data %p is NULL\n",
                 peerNode, parser_data);
        return AC_FAILURE;
    }
    
    //Copy the enrty key...
    memcpy(&peerNode->key, &app->key, sizeof(peerNode->key));

    //Update ARP adjancency records for this packet
    if (app->direction == 0) { //TODO: RX
        arpInfo->rxPktByteCnt += app->pktSz;
        arpInfo->rxPktCnt++;
    
        delta = time - arpInfo->lastPktRcvdTime;
        if ((delta < arpInfo->minRxDelta) || !(arpInfo->minRxDelta)) {
            arpInfo->minRxDelta = delta;
        } else if (delta > arpInfo->minRxDelta) {
            arpInfo->maxRxDelta = delta;
        }
        delta = time - arpInfo->lastPktRcvdTime;
        arpInfo->lastPktRcvdTime = time;
    } else {
        arpInfo->txPktByteCnt += app->pktSz;
        arpInfo->txPktCnt++;

        //TODO for Tx
    }

    printf ("Updated ARP table with appId:%d, portId:%p \n", app->key.appId, app->key.portId);
    return AC_SUCCESS;
}


/* 
 * acPortAndAppInfoUpdate
 *
 * Entry function to handle the ARP protocol analytics
 *
 * Notes: 
 */
extern acPortAppTbl_t      acPortAppDb[AC_MAX_PORTS][AC_MAX_APPS];
extern acAppTbl_t          acAppDb[AC_MAX_APPS];
extern acPortTbl_t         acPortDb[AC_MAX_PORTS];

void 
acPortAndAppInfoUpdate(acPeerTblKey_t *pktInfoKey, uint32_t appIndex,
                       acAppParser_t *parsed_data)
{
    acPortTbl_t    *portEntry = NULL;
    acAppTbl_t     *appEntry = NULL;
    acPortAppTbl_t *portAppEntry = NULL;


    if (!pktInfoKey || !parsed_data) {
        printf("%s: Input is null\n", __func__);
        return;
    }

    if ((appIndex >= AC_MAX_APP_INDEX) ||
        (pktInfoKey->portId >= AC_MAX_PORTS) ) {
        printf("%s: Invalid appIndex:%d, portId:%d\n", __func__, appIndex, pktInfoKey->portId);
        return;
    }

    //#1. Update Port Stats
    portEntry = &acPortDb[pktInfoKey->portId];
    appEntry = &acAppDb[appIndex];
    portAppEntry = &acPortAppDb[pktInfoKey->portId][appIndex];
    if (parsed_data->direction == 0) { //RX
        portEntry->rxPktCnt++;
        appEntry->rxPktCnt++;
        portAppEntry->rxPktCnt++;
    } else {
        portEntry->txPktCnt++;
        appEntry->txPktCnt++;
        portAppEntry->txPktCnt++;
    }

    return;
}

uint32_t acAppIdToIndex(uint32_t appId)
{
    uint32_t index = 0;

    switch (appId) {
    case AC_APP_ARP_ID:
        index = AC_APP_ARP_INDEX;
        break;
    default:
        index = AC_MAX_APP_INDEX;
    }

    return index;
}


/* README: Enty routine to aCoPP module
 *
 * acAppPktHandler
 *
 * Entry function to handle the control protocol analytics
 *
 * Notes: 
 */
    acReturn_t
acAppPktHandler(acPeerTblKey_t *pktInfoKey,  acAppParser_t *data)
{
    void             *peerNode = NULL;
    uint32_t          index = 0;

    printf("%s: index:%d, appId:0x%x func:%p\n", __func__, 
            index, pktInfoKey->appId, appProtoHandlers[index].func);

    index = acAppIdToIndex(pktInfoKey->appId);

    printf("%s: index:%d, appId:0x%x func:%p\n", __func__, 
            index, pktInfoKey->appId, appProtoHandlers[index].func);

    if ( (index < AC_MAX_APP_INDEX) && (appProtoHandlers[index].func) ) {

        acPortAndAppInfoUpdate(pktInfoKey, index, data);

        /*
         * Find the peer entry from the peer Tbl
         */
        peerNode = acPeerTblEntryFind(pktInfoKey);
        if (peerNode == NULL) {
            peerNode = acPeerTblEntryCreate(pktInfoKey);
        }

        if (peerNode) {
            appProtoHandlers[index].func(peerNode, data);
        }
    }

    return AC_SUCCESS;
}



