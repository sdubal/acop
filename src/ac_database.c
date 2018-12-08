/*file: ac_database.c
 *
 * This file defines database APIs to store the control protocol analystics data
 *
 * Notes: 
 *
 * Author: Umesha G.M (ugm@cisco.com)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/ac_types.h"
#include "../include/ac_database.h"
#include "../include/ac_app_defs.h"
#include "../include/ac_app_api.h"


/*
 * Port specific information on the cotrol plane
 */
acPortTbl_t         acPortDb[AC_MAX_PORTS];

/*
 * APP specific information on the control plane
 * Peer or host entry informtion database
 */
acAppTbl_t          acAppDb[AC_MAX_APPS];


/*
 * ARRAY: Traversing the peer table using port and Application protocol
 */
acPortAppTbl_t      acPortAppDb[AC_MAX_PORTS][AC_MAX_APPS];

/*
 * Peer or host entry informtion database.
 * HASH table: serach using 5 tuple info. 
 * HASH = PORT ^ SRC_IP ^ DST_IP ^ APPID ^ VLANID 
 * Refer the hash function fo calculating the hash to identify the node of the entry in the peer table.
 *
 */
acPeerTbl_t         acPeerDb[AC_MAX_PEER_ENTRIES];


void acPortAppTblEntryAdd(acPeerTblKey_t *key, acPeerNode_t *entry);
 

/*
 * hash calculation for the aCopp Tablesh
 *
 */
uint32_t
acHashIndexCalculate(uchar8_t key[], uchar8_t keyLen)
{
    uint32_t hashIndex = 0;
    uint32_t keysum = 0;
    uint32_t i = 0;

    //Caclualte 2 byte index to allow more indexes
    for (i = 0; i < keyLen; i++) {
        keysum ^= key[i] ;
#if 0
        if (++i < keyLen) {
            keysum ^= (key[i] << 8 & 0xff00);
        }
#endif
    }

    hashIndex = keysum / AC_MAX_PEER_TBL_HASH;
    printf("hashsum = %d, hasIndex:%d\n", keysum, hashIndex);

    return (hashIndex);
}


/*
 * Peer entry insert into HASH table
 *
 */
inline void *
acPeerTblEntryInsert(acPeerTblKey_t *key, acPeerNode_t  *entry)
{
    uint32_t hashIndex = 0;

    hashIndex = acHashIndexCalculate((uchar8_t*)key, sizeof(acPeerTblKey_t));

    if (acPeerDb[hashIndex].headp == NULL) {
        acPeerDb[hashIndex].headp = acPeerDb[hashIndex].tailp = entry;
        printf("inserted the entry to peerTbl head: %p\n", entry);
    } else {
        entry->prevp = acPeerDb[hashIndex].tailp;;
        entry->nextp = NULL;
        acPeerDb[hashIndex].tailp = entry;
        printf("inserted the entry to peerTbl tail\n");
    }

    return entry;  //returns the entry which is deleted.
}

/*
 * Peer entry delete from the HASH table
 *
 */
inline acReturn_t
acPeerTblEntryDelete(acPeerTblKey_t *key)
{
    acPeerNode_t  *entry = NULL;
    uint32_t       hashIndex = 0;
    uchar8_t       found = 0;

    hashIndex = acHashIndexCalculate((uchar8_t*)key, sizeof(acPeerTblKey_t));

    entry = acPeerDb[hashIndex].headp;
    for (;entry != NULL; entry = entry->nextp) {
        if (memcmp(&entry->key, key, sizeof(acPeerTblKey_t)) == 0) {
            found = 1;
            break;
        }
    }

    if (found) {
        if (acPeerDb[hashIndex].headp == entry) {
            //removing head node;
            acPeerDb[hashIndex].headp = acPeerDb[hashIndex].headp->nextp;
        } else {
            entry->prevp = entry->nextp;
        }

        free(entry);
    }

    printf ("%s: deleted the entry %s \n", __func__, found ? "true":"false");

    return found ? AC_SUCCESS : AC_NOT_FOUND;
}

/*
 * Peer entry find from the HASH table
 *
 */
void *
acPeerTblEntryFind (acPeerTblKey_t *key)
{
    acPeerNode_t  *entry = NULL;
    uint32_t       hashIndex = 0;

    hashIndex = acHashIndexCalculate((uchar8_t*)key, sizeof(acPeerTblKey_t));

    entry = acPeerDb[hashIndex].headp;
    printf ("%s: peerTbl head entry %p at hashInbdex:%d\n", __func__, entry, hashIndex);

    for (;entry != NULL; entry = entry->nextp) {
        if (memcmp(&entry->key, key, sizeof(acPeerTblKey_t)) == 0) {
            break;
        }

        printf ("%s: not at entry index %d \n", __func__, index);
        printf ("port:%d, %d, vlaidId:%d, %d, appId:%d, %d\n", 
                key->portId, entry->key.portId, 
                key->vlanId, entry->key.vlanId, 
                key->appId, entry->key.appId);
    }

    printf ("%s: found entry is %p \n", __func__, entry);
    return entry;
}


/*
 * Peer entry insert into HASH table.
 * This creates the entry and addes into the table. It does not 
 * check if the entry already exists in the table.
 *
 */
void*
acPeerTblEntryCreate(acPeerTblKey_t *key)
{
    acPeerNode_t  *entry = NULL;
    uint32_t       hashIndex = 0;

    hashIndex = acHashIndexCalculate((uchar8_t*)key, sizeof(acPeerTblKey_t));

    printf ("\ncreate an entry \n");
    entry = (acPeerNode_t *) malloc(sizeof(acPeerNode_t));
    if (entry) {
        memset(entry, 0, sizeof(acPeerNode_t));
        memcpy(&entry->key, key, sizeof(acPeerTblKey_t));
        acPeerTblEntryInsert(key, entry);
        acPortAppTblEntryAdd(key, entry);
        printf ("created a entry with key with portId:%d, vlanId:%d, appId:%d, entry : %p\n",
                entry->key.portId, entry->key.vlanId, entry->key.appId, entry);
    }

    return entry; 
}



/*
 * Peer entry insert into HASH table.
 * This creates the entry and addes into the table. It does not 
 * check if the entry already exists in the table.
 *
 */
inline void *
acPeerTblEntryFindAndCreate(acPeerTblKey_t *key)
{
    acPeerNode_t  *entry = NULL;

    entry = acPeerTblEntryFind(key);
    if (entry) {
        return entry;
    }

    entry = acPeerTblEntryCreate(key);
    if (entry) {
        acPortAppTblEntryAdd(key, entry);
    }

    return entry; 
}



/**************************************************************
 * 
 *  PORT APPID TBL APIs
 * 
 *************************************************************/
/*
 * Add the peer entry into the portApp table
 */
void
acPortAppTblEntryAdd(acPeerTblKey_t *key, acPeerNode_t *entry)
{
    uint32_t          index = 0;
    acPortAppTbl_t   *portAppEntry = NULL;

    index = acAppIdToIndex(key->appId);
    portAppEntry = &acPortAppDb[key->portId][index];

    if (portAppEntry->headp == NULL) {
        portAppEntry->headp = entry;
        portAppEntry->tailp = entry;
    } else {
        portAppEntry->tailp = entry;
        portAppEntry->tailp->nextp = NULL;
    }
 
    return;
}


#if 0
int main ()
{
    acPeerNode_t  *entry = NULL;
    uint32_t hashIndex = 0;
    //acPeerTblKey_t  key1 = {1,1,111,0,{0,}};
    acPeerTblKey_t  key2 = {2,11,222,0,{0,}};
    acPeerTblKey_t  key3 = {3,11,333,0,{0,}};
    acPeerTblKey_t  key11 = {1,11,111,0,{0,}};
    acPeerTblKey_t  key22 = {2,11,222,0,{0,}};
    acPeerTblKey_t  key222 = {2,11,222,3,{0,}};
    uint32_t  keyLen = sizeof(acPeerTblKey_t);

#if 0
    hashIndex = acHashIndexCalculate((uchar8_t *) &key1, keyLen);
    printf ("hash index 1= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key2, keyLen);
    printf ("hash index 2= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key3, keyLen);
    printf ("hash index 3= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key11, keyLen);
    printf ("hash index 1= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key22, keyLen);
    printf ("hash index 2= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key222, keyLen);
    printf ("hash index 2= %d\n", hashIndex);
    hashIndex = acHashIndexCalculate((uchar8_t *)&key222, keyLen);
    printf ("hash index= %d\n", hashIndex);


    entry = acPeerTblEntryFindAndCreate(&key1);
    entry = acPeerTblEntryFind(&key1);
    
    printf ("entry portId:%d\n", entry->key.portId);
    printf ("entry appId:%d\n", entry->key.portId);
    printf ("entry vlanId:%d\n", entry->key.vlanId);
    
    acPeerTblEntryDelete(&key1);
    entry = acPeerTblEntryFind(&key1);
    printf ("After Delete entry :%p\n", entry);
    

#endif
    acPeerTblKey_t  key1 = {0,0x0806,1,{0,},{0,}};
    acAppParser_t parser_data = {{0, 0x0806, 1,{0,}, {0,}}, 0,22};
    printf ("Update an entry at port:%d, appId:0x%x, pktSz:%d\n",
            parser_data.key.portId, parser_data.key.appId, parser_data.pktSz);

    acAppPktHandler(&key1, &parser_data);
    entry = acPeerTblEntryFind(&key1);
    printf ("\n find entry : %p\n", entry);

    acPeerTblEntryDelete(&key1);
    entry = acPeerTblEntryFind(&key1);
    printf ("After Delete entry :%p\n", entry);
    //printf ("entry portId:%d\n", entry->key.portId);
    //printf ("entry appId:%d\n", entry->key.portId);
    //printf ("entry vlanId:%d\n", entry->key.vlanId);

}
#endif 
