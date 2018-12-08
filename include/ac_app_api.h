/*
 * ac_app_api.h - Application/Protocol APIs.
 *
 * author: Umesha G.M (ugm@cisco.com)
 */

#ifndef __AC_APP_API_H__
#include <time.h>
#include "ac_types.h"
#include "ac_app_defs.h"
#include "ac_database.h"


typedef acReturn_t (*acAppHandlerFunc_p)(acPeerNode_t *peer_node, acAppParser_t *app_Data);

typedef struct acAppHandlers_s {
    acAppIndexMap_t         index;  //Mapped array index for the protocol
    acAppIdentifyMap_t      protId; //Eth Type or Application Protocol differentiator
    acAppHandlerFunc_p      func;
}acAppHandlers_t;




/***********************************************************
 * PROTOCOL/APP PACKET HNADLERS 
 *********************************************************/
acReturn_t acAppPktHandler(acPeerTblKey_t *pktInfoKey, acAppParser_t *data);
acReturn_t acAppArpPktHandler(acPeerNode_t *peerNode, acAppParser_t *app_data);
uint32_t acAppIdToIndex(uint32_t appId);


#endif //__AC_APP_API_H__
