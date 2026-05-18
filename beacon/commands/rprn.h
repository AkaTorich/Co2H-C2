

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 05:14:07 2038
 */
/* Compiler settings for C:/Users/psysh/OneDrive/Desktop/Co2H/beacon/commands/rprn.idl:
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


#ifndef __rprn_h__
#define __rprn_h__

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


/* interface __MIDL_itf_rprn_0000_0000 */
/* [local] */ 

typedef unsigned long DWORD;

typedef unsigned short WORD;

typedef /* [context_handle] */ void *PRINTER_HANDLE;

typedef struct _DEVMODE_CONTAINER
    {
    DWORD cbBuf;
    /* [unique][size_is] */ byte *pDevMode;
    } 	DEVMODE_CONTAINER;

typedef struct _RPC_V2_NOTIFY_OPTIONS_TYPE
    {
    WORD Type;
    WORD Reserved0;
    DWORD Reserved1;
    DWORD Reserved2;
    DWORD Count;
    /* [unique][size_is] */ WORD *pFields;
    } 	RPC_V2_NOTIFY_OPTIONS_TYPE;

typedef struct _RPC_V2_NOTIFY_OPTIONS
    {
    DWORD Version;
    DWORD Reserved;
    DWORD Count;
    /* [unique][size_is] */ RPC_V2_NOTIFY_OPTIONS_TYPE *pTypes;
    } 	RPC_V2_NOTIFY_OPTIONS;



extern RPC_IF_HANDLE __MIDL_itf_rprn_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_rprn_0000_0000_v0_0_s_ifspec;

#ifndef __RPRN_INTERFACE_DEFINED__
#define __RPRN_INTERFACE_DEFINED__

/* interface RPRN */
/* [implicit_handle][version][uuid] */ 

void _Rpc0( void);

DWORD RpcOpenPrinter( 
    /* [unique][string][in] */ wchar_t *pPrinterName,
    /* [out] */ PRINTER_HANDLE *pHandle,
    /* [unique][string][in] */ wchar_t *pDatatype,
    /* [in] */ DEVMODE_CONTAINER *pDevModeContainer,
    /* [in] */ DWORD AccessRequired);

void _Rpc2( void);

void _Rpc3( void);

void _Rpc4( void);

void _Rpc5( void);

void _Rpc6( void);

void _Rpc7( void);

void _Rpc8( void);

void _Rpc9( void);

void _Rpc10( void);

void _Rpc11( void);

void _Rpc12( void);

void _Rpc13( void);

void _Rpc14( void);

void _Rpc15( void);

void _Rpc16( void);

void _Rpc17( void);

void _Rpc18( void);

void _Rpc19( void);

void _Rpc20( void);

void _Rpc21( void);

void _Rpc22( void);

void _Rpc23( void);

void _Rpc24( void);

void _Rpc25( void);

void _Rpc26( void);

void _Rpc27( void);

void _Rpc28( void);

void _Rpc29( void);

void _Rpc30( void);

void _Rpc31( void);

void _Rpc32( void);

void _Rpc33( void);

void _Rpc34( void);

void _Rpc35( void);

void _Rpc36( void);

void _Rpc37( void);

void _Rpc38( void);

void _Rpc39( void);

void _Rpc40( void);

void _Rpc41( void);

void _Rpc42( void);

void _Rpc43( void);

void _Rpc44( void);

void _Rpc45( void);

void _Rpc46( void);

void _Rpc47( void);

void _Rpc48( void);

void _Rpc49( void);

void _Rpc50( void);

void _Rpc51( void);

void _Rpc52( void);

void _Rpc53( void);

void _Rpc54( void);

void _Rpc55( void);

void _Rpc56( void);

void _Rpc57( void);

void _Rpc58( void);

void _Rpc59( void);

void _Rpc60( void);

void _Rpc61( void);

void _Rpc62( void);

void _Rpc63( void);

void _Rpc64( void);

DWORD RpcRemoteFindFirstPrinterChangeNotificationEx( 
    /* [in] */ PRINTER_HANDLE hPrinter,
    /* [in] */ DWORD fdwFlags,
    /* [in] */ DWORD fdwOptions,
    /* [unique][string][in] */ wchar_t *pszLocalMachine,
    /* [in] */ DWORD dwPrinterLocal,
    /* [unique][in] */ RPC_V2_NOTIFY_OPTIONS *pOptions);


extern handle_t hRprnBinding;


extern RPC_IF_HANDLE RPRN_v1_0_c_ifspec;
extern RPC_IF_HANDLE RPRN_v1_0_s_ifspec;
#endif /* __RPRN_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER PRINTER_HANDLE_rundown( PRINTER_HANDLE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


