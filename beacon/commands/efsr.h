

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 05:14:07 2038
 */
/* Compiler settings for C:/Users/psysh/OneDrive/Desktop/Co2H/beacon/commands/efsr.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : dce , ms_ext, c_ext, robust
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


#ifndef __efsr_h__
#define __efsr_h__

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


#ifndef __efsrpc_INTERFACE_DEFINED__
#define __efsrpc_INTERFACE_DEFINED__

/* interface efsrpc */
/* [version][uuid] */ 

typedef /* [public][public] */ struct __MIDL_efsrpc_0001
    {
    unsigned long cbData;
    /* [size_is] */ unsigned char *pbData;
    } 	EFSR_RPC_BLOB;

long EfsRpcOpenFileRaw( 
    /* [in] */ handle_t binding_h,
    /* [out] */ long *pvContext,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ long Flags);

long Opnum1Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum2Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum3Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum4Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum5Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum6Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum7Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum8Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum9Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum10Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum11Reserved( 
    /* [in] */ handle_t IDL_handle);

long Opnum12Reserved( 
    /* [in] */ handle_t IDL_handle);

long EfsRpcDuplicateEncryptionInfoFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *SrcFileName,
    /* [string][in] */ wchar_t *DestFileName,
    /* [in] */ unsigned long dwCreationDisposition,
    /* [in] */ unsigned long dwDesiredAttributes,
    /* [unique][in] */ EFSR_RPC_BLOB *pRelativeSD,
    /* [in] */ unsigned long bInheritHandle);



extern RPC_IF_HANDLE efsrpc_v1_0_c_ifspec;
extern RPC_IF_HANDLE efsrpc_v1_0_s_ifspec;
#endif /* __efsrpc_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


