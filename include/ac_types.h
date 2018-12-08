/*
 * acopp_types.h
 *
 * type definitions.
 */

#ifndef __ACOPP_TYPES_H__
#define __ACOPP_TYPES_H__


#ifndef char8_t
typedef char char8_t;
#endif

#ifndef ushort16_t
typedef unsigned char uchar8_t;
#endif

#ifndef ushort16_t
typedef short short16_t;
#endif

#ifndef ushort16_t
typedef unsigned short ushort16_t;
#endif

#ifndef int32_t
typedef int int32_t;
#endif

#ifndef uint32_t
typedef unsigned int uint32_t;
#endif

#ifndef int64_t
//typedef signed long long int int64_t;
typedef signed long long int ac_int64_t;
#endif

#ifndef uint64_t
//typedef unsigned long long int uint64_t;
typedef unsigned long long int ac_uint64_t;

#endif



enum {
    IP_ADDR_TYPE_V4 = 0,
    IP_ADDR_TYPE_V6 = 1,
};

typedef struct acIpAddt_s {
    uchar8_t        type;                       //V4 or V6 address;       
    union {
        uint32_t    v4addr;                     //Host order.
        uchar8_t    v6addr[16];                 //
    }addr;
}acIpAddr_t;




typedef enum AC_RETURN_s {
    AC_SUCCESS = 0,
    AC_FAILURE = 1,
    AC_NOT_EXISTS,
    AC_NOT_FOUND,
    AC_INVALID_PARAMS,
    AC_WRONG_IP,

}acReturn_t;


#endif /* __ACOPP_TYPES_H__ */


