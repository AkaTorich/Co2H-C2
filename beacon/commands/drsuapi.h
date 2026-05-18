

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 05:14:07 2038
 */
/* Compiler settings for C:/Users/psysh/OneDrive/Desktop/Co2H/beacon/commands/drsuapi.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : dce , ms_ext, app_config, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __drsuapi_h__
#define __drsuapi_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_drsuapi_0000_0000 */
/* [local] */ 

typedef unsigned long DWORD;

typedef unsigned long ULONG;

typedef unsigned short USHORT;

typedef long LONG;

typedef wchar_t WCHAR;

#ifndef GUID_DEFINED
#define GUID_DEFINED
typedef /* [public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0001
    {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    byte Data4[ 8 ];
    } 	GUID;

#endif /* GUID_DEFINED */
typedef hyper HYPER_USEC_TIMER;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0002
    {
    DWORD cb;
    /* [size_is] */ byte *rgb;
    } 	DRS_EXTENSIONS;

typedef /* [public][public][public][public][public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0003
    {
    ULONG structLen;
    ULONG SidLen;
    GUID Guid;
    byte Sid[ 28 ];
    USHORT NameLen;
    /* [size_is] */ WCHAR *StringName;
    } 	DSNAME;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0004
    {
    DWORD length;
    /* [unique][size_is] */ byte *elements;
    } 	SCHEMA_PREFIX_OID;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0005
    {
    DWORD ndx;
    SCHEMA_PREFIX_OID prefix;
    } 	SCHEMA_PREFIX;

typedef /* [public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0006
    {
    DWORD PrefixCount;
    /* [unique][size_is] */ SCHEMA_PREFIX *pSchema;
    } 	SCHEMA_PREFIX_TABLE;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0007
    {
    GUID uuidDsa;
    hyper usnHighPropUpdate;
    } 	UPTODATE_CURSOR_V1;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0008
    {
    DWORD dwVersion;
    hyper timeLastSyncSuccess;
    DWORD cNumCursors;
    /* [size_is] */ UPTODATE_CURSOR_V1 *rgCursors;
    } 	UPTODATE_VECTOR_V1_EXT;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0009
    {
    GUID uuidDsa;
    hyper usnHighPropUpdate;
    hyper timeLastSyncSuccess;
    } 	UPTODATE_CURSOR_V2;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0010
    {
    DWORD dwVersion;
    DWORD dwReserved1;
    DWORD cNumCursors;
    /* [size_is] */ UPTODATE_CURSOR_V2 *rgCursors;
    } 	UPTODATE_VECTOR_V2_EXT;

typedef /* [public][public][public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0011
    {
    DWORD dwVersion;
    DWORD dwReserved1;
    DWORD cNumProps;
    /* [size_is] */ DWORD *rgPartialAttr;
    } 	PARTIAL_ATTR_VECTOR_V1_EXT;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0012
    {
    GUID uuidDsaObjDest;
    GUID uuidInvocIdSrc;
    /* [unique] */ DSNAME *pNC;
    /* [unique] */ UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
    SCHEMA_PREFIX_TABLE PrefixTableDest;
    ULONG ulFlags;
    ULONG cMaxObjects;
    ULONG cMaxBytes;
    ULONG ulExtendedOp;
    HYPER_USEC_TIMER liFsmoInfo;
    /* [unique] */ PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
    /* [unique] */ PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetMove;
    } 	DRS_MSG_GETCHGREQ_V8;

typedef /* [public][public][switch_type] */ union __MIDL___MIDL_itf_drsuapi_0000_0000_0013
    {
    /* [case()] */ DRS_MSG_GETCHGREQ_V8 V8;
    } 	DRS_MSG_GETCHGREQ;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0014
    {
    DWORD valLen;
    /* [unique][size_is] */ byte *pVal;
    } 	ATTRVAL;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0015
    {
    DWORD valCount;
    /* [unique][size_is] */ ATTRVAL *pAVal;
    } 	ATTRVALBLOCK;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0016
    {
    DWORD attrTyp;
    ATTRVALBLOCK AttrVal;
    } 	ATTR;

typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0017
    {
    DWORD attrCount;
    /* [unique][size_is] */ ATTR *pAttr;
    } 	ATTRBLOCK;

typedef /* [public][public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0018
    {
    /* [unique] */ DSNAME *pName;
    ULONG ulFlags;
    ATTRBLOCK AttrBlock;
    } 	ENTINF;

typedef struct REPLENTINFLIST_s
    {
    ENTINF Entinf;
    /* [unique] */ struct REPLENTINFLIST_s *pNextEntInf;
    /* [unique] */ byte *pMetaDataExt;
    } 	REPLENTINFLIST;

typedef /* [public][public][public] */ struct __MIDL___MIDL_itf_drsuapi_0000_0000_0019
    {
    DWORD dwVersion;
    DWORD dwReserved1;
    GUID uuidDsaObjSrc;
    GUID uuidInvocIdSrc;
    /* [unique] */ DSNAME *pNC;
    ULONG ulExtendedRet;
    ULONG cNumObjects;
    ULONG cNumBytes;
    /* [unique] */ REPLENTINFLIST *pObjects;
    long fMoreData;
    ULONG cNumNcSizeObjects;
    HYPER_USEC_TIMER cbNcSizeBytes;
    SCHEMA_PREFIX_TABLE PrefixTableSrc;
    /* [unique] */ UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
    DWORD dwDRSError;
    } 	DRS_MSG_GETCHGREPLY_V6;

typedef /* [public][public][switch_type] */ union __MIDL___MIDL_itf_drsuapi_0000_0000_0020
    {
    /* [case()] */ DRS_MSG_GETCHGREPLY_V6 V6;
    } 	DRS_MSG_GETCHGREPLY;



extern RPC_IF_HANDLE __MIDL_itf_drsuapi_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_drsuapi_0000_0000_v0_0_s_ifspec;

#ifndef __drsuapi_INTERFACE_DEFINED__
#define __drsuapi_INTERFACE_DEFINED__

/* interface drsuapi */
/* [version][uuid] */ 

typedef /* [context_handle] */ void *DRS_HANDLE;

ULONG IDL_DRSBind( 
    /* [in] */ handle_t rpc_handle,
    /* [unique][in] */ GUID *puuidClientDsa,
    /* [unique][in] */ DRS_EXTENSIONS *pextClient,
    /* [out] */ DRS_EXTENSIONS **ppextServer,
    /* [ref][out] */ DRS_HANDLE *phDrs);

void _Opnum1( 
    /* [in] */ handle_t IDL_handle);

void _Opnum2( 
    /* [in] */ handle_t IDL_handle);

ULONG IDL_DRSGetNCChanges( 
    /* [ref][in] */ DRS_HANDLE *phDrs,
    /* [in] */ DWORD dwInVersion,
    /* [switch_is][in] */ DRS_MSG_GETCHGREQ *pmsgIn,
    /* [ref][out] */ DWORD *pdwOutVersion,
    /* [switch_is][ref][out] */ DRS_MSG_GETCHGREPLY *pmsgOut);

ULONG IDL_DRSUnbind( 
    /* [ref][out][in] */ DRS_HANDLE *phDrs);



extern RPC_IF_HANDLE drsuapi_v4_0_c_ifspec;
extern RPC_IF_HANDLE drsuapi_v4_0_s_ifspec;
#endif /* __drsuapi_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER DRS_HANDLE_rundown( DRS_HANDLE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


