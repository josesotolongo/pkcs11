/*
 * dextapi.h 
 * Top level header file for SafeNet D-extension APIs. 
 *
 * Copyright © 2012 SafeNet, Inc. All rights reserved.
 */

#ifndef _DEXTAPI_H_
#define _DEXTAPI_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

/* All the various PKCS #11 types and #define'd values are in the
 * file pkcs11t.h. 
 */
#include "pkcs11t.h"
 
#define __PASTE(x,y)      x##y

/* ==============================================================
 * Define the data structures and the "extern" form of all the 
 * D-extension entry points.
 * ==============================================================
 */
#define CK_NEED_DEFINE_STRUCTS  1
#define CK_NEED_ARG_LIST        1
#define CK_DEXT_FUNCTION_INFO(returnType, name) \
  extern CK_DECLARE_FUNCTION(returnType, name)
 
/* dextskey6500f.h has all the information about the skey6500 D-Extension
 * function prototypes. 
 */
#include "dextskey6500f.h"    // skey6500 D-extensions

#undef CK_NEED_DEFINE_STRUCTS  
#undef CK_NEED_ARG_LIST
#undef CK_DEXT_FUNCTION_INFO
 
 
/* ==============================================================
 * Define the typedef form of all the D-extension entry points.  
 * That is, foreach function D_XXX, define a type CK_D_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */ 
#define CK_NEED_ARG_LIST        1
#define CK_DEXT_FUNCTION_INFO(returnType, name) \
  typedef CK_DECLARE_FUNCTION_POINTER(returnType, __PASTE(CK_,name))
 
/* dextskey6500f.h has all the information about the skey6500 D-Extension
 * function prototypes. 
 */
#include "dextskey6500f.h"    // skey6500 token D-extensions
  
#undef CK_NEED_ARG_LIST
#undef CK_DEXT_FUNCTION_INFO
 
/* ==============================================================
 * Define structed vector of SafeNet D-extension entry points.  
 * A CK_DEXT_FUNCTION_LIST contains a CK_VERSION indicating a D-ext 
 * version and then a whole slew of function pointers to the routines 
 * of the SafeNet D-extension APIs.
 * ==============================================================
 */
#define CK_DEXT_FUNCTION_INFO(retutnType, name) \
   __PASTE(CK_,name) name;

struct CK_DEXT_FUNCTION_LIST {  
   CK_VERSION    Dext_version;  /* D-Extension API version */
 
 /* Pile all the function pointers into the CK_DEXT_FUNCTION_LIST. 
  * dextskey6500f.h has all the information about the D Extension
  * function prototypes. 
  */
#include "dextskey6500f.h"  
};

#undef CK_DEXT_FUNCTION_INFO

#undef __PASTE
 
#ifdef __cplusplus
}
#endif
 
#endif  /* _DEXTAPI_H */
 