/*
 * ac_app_defs.h - Application/Protocol definitions.
 *
 * author: Umesha G.M (ugm@cisco.com)
 */

#ifndef __AC_APP_DEFS_H__
#define __AC_APP_DEFS_H__

#include <time.h>
#include "ac_types.h"

typedef enum acAppIndexMap_e {
   AC_APP_ARP_INDEX                        = 0,
   AC_APP_ICMP_INDEX                       = 1,

   AC_MAX_APP_INDEX
}acAppIndexMap_t;

typedef enum acAppIdentificationMap_e {
    AC_APP_ARP_ID           = 0x0806,   //Application protocol Identification number
    AC_APP_ICMP_ID          = 0x01,
    
    AC_APP_MAX = 0xFFFF
}acAppIdentifyMap_t;


 /********************************************************************
  * APPLICATION PROTOCOL HANDLERS DEFINITIONS - START
  ********************************************************************/
typedef struct acAppArpProtInfo_s {
 
    uint32_t        state;
    uint32_t        rxPktCnt;
    uint32_t        txPktCnt;
    uint32_t        rxPktByteCnt;
    uint32_t        txPktByteCnt;
    uint32_t        txPktRate;
    uint32_t        txPktRate_cnt;
    uint32_t        rxPktRate;
    uint32_t        rxPktRate_cnt;

    time_t          lastPktRcvdTime;
    time_t          lastTpkTxdTime;
    
    time_t          minRxDelta;
    time_t          maxRxDelta;
}acAppArpProtInfo_t;
 

 /********************************************************************
  * APPLICATION PROTOCOL HANDLERS DEFINITIONS - END
  * ******************************************************************/


#endif //__AC_APP_DEFS_H__
