

/* this ALWAYS GENERATED file contains the RPC client stubs */


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

#if defined(_M_AMD64)


#pragma warning( disable: 4049 )  /* more than 64k source lines */
#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/
#pragma warning( disable: 4100 ) /* unreferenced arguments in x86 call */

#pragma optimize("", off ) 

#include <string.h>

#include "rprn.h"

#define TYPE_FORMAT_STRING_SIZE   127                               
#define PROC_FORMAT_STRING_SIZE   1801                              
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _rprn_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } rprn_MIDL_TYPE_FORMAT_STRING;

typedef struct _rprn_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } rprn_MIDL_PROC_FORMAT_STRING;

typedef struct _rprn_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } rprn_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax_2_0 = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};

#if defined(_CONTROL_FLOW_GUARD_XFG)
#define XFG_TRAMPOLINES(ObjectType)\
NDR_SHAREABLE unsigned long ObjectType ## _UserSize_XFG(unsigned long * pFlags, unsigned long Offset, void * pObject)\
{\
return  ObjectType ## _UserSize(pFlags, Offset, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserMarshal_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserMarshal(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserUnmarshal_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserUnmarshal(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE void ObjectType ## _UserFree_XFG(unsigned long * pFlags, void * pObject)\
{\
ObjectType ## _UserFree(pFlags, (ObjectType *)pObject);\
}
#define XFG_TRAMPOLINES64(ObjectType)\
NDR_SHAREABLE unsigned long ObjectType ## _UserSize64_XFG(unsigned long * pFlags, unsigned long Offset, void * pObject)\
{\
return  ObjectType ## _UserSize64(pFlags, Offset, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserMarshal64_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserMarshal64(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserUnmarshal64_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserUnmarshal64(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE void ObjectType ## _UserFree64_XFG(unsigned long * pFlags, void * pObject)\
{\
ObjectType ## _UserFree64(pFlags, (ObjectType *)pObject);\
}
#define XFG_BIND_TRAMPOLINES(HandleType, ObjectType)\
static void* ObjectType ## _bind_XFG(HandleType pObject)\
{\
return ObjectType ## _bind((ObjectType) pObject);\
}\
static void ObjectType ## _unbind_XFG(HandleType pObject, handle_t ServerHandle)\
{\
ObjectType ## _unbind((ObjectType) pObject, ServerHandle);\
}
#define XFG_TRAMPOLINE_FPTR(Function) Function ## _XFG
#define XFG_TRAMPOLINE_FPTR_DEPENDENT_SYMBOL(Symbol) Symbol ## _XFG
#else
#define XFG_TRAMPOLINES(ObjectType)
#define XFG_TRAMPOLINES64(ObjectType)
#define XFG_BIND_TRAMPOLINES(HandleType, ObjectType)
#define XFG_TRAMPOLINE_FPTR(Function) Function
#define XFG_TRAMPOLINE_FPTR_DEPENDENT_SYMBOL(Symbol) Symbol
#endif


extern const rprn_MIDL_TYPE_FORMAT_STRING rprn__MIDL_TypeFormatString;
extern const rprn_MIDL_PROC_FORMAT_STRING rprn__MIDL_ProcFormatString;
extern const rprn_MIDL_EXPR_FORMAT_STRING rprn__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: __MIDL_itf_rprn_0000_0000, ver. 0.0,
   GUID={0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}} */


/* Standard interface: RPRN, ver. 1.0,
   GUID={0x12345678,0x1234,0xABCD,{0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAB}} */

handle_t hRprnBinding;


static const RPC_CLIENT_INTERFACE RPRN___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x12345678,0x1234,0xABCD,{0xEF,0x00,0x01,0x23,0x45,0x67,0x89,0xAB}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE RPRN_v1_0_c_ifspec = (RPC_IF_HANDLE)& RPRN___RpcClientInterface;
#ifdef __cplusplus
namespace {
#endif

extern const MIDL_STUB_DESC RPRN_StubDesc;
#ifdef __cplusplus
}
#endif

static RPC_BINDING_HANDLE RPRN__MIDL_AutoBindHandle;


void _Rpc0( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[0],
                  0);
    
}


DWORD RpcOpenPrinter( 
    /* [unique][string][in] */ wchar_t *pPrinterName,
    /* [out] */ PRINTER_HANDLE *pHandle,
    /* [unique][string][in] */ wchar_t *pDatatype,
    /* [in] */ DEVMODE_CONTAINER *pDevModeContainer,
    /* [in] */ DWORD AccessRequired)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[26],
                  pPrinterName,
                  pHandle,
                  pDatatype,
                  pDevModeContainer,
                  AccessRequired);
    return ( DWORD  )_RetVal.Simple;
    
}


void _Rpc2( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[88],
                  0);
    
}


void _Rpc3( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[114],
                  0);
    
}


void _Rpc4( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[140],
                  0);
    
}


void _Rpc5( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[166],
                  0);
    
}


void _Rpc6( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[192],
                  0);
    
}


void _Rpc7( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[218],
                  0);
    
}


void _Rpc8( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[244],
                  0);
    
}


void _Rpc9( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[270],
                  0);
    
}


void _Rpc10( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[296],
                  0);
    
}


void _Rpc11( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[322],
                  0);
    
}


void _Rpc12( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[348],
                  0);
    
}


void _Rpc13( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[374],
                  0);
    
}


void _Rpc14( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[400],
                  0);
    
}


void _Rpc15( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[426],
                  0);
    
}


void _Rpc16( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[452],
                  0);
    
}


void _Rpc17( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[478],
                  0);
    
}


void _Rpc18( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[504],
                  0);
    
}


void _Rpc19( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[530],
                  0);
    
}


void _Rpc20( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[556],
                  0);
    
}


void _Rpc21( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[582],
                  0);
    
}


void _Rpc22( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[608],
                  0);
    
}


void _Rpc23( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[634],
                  0);
    
}


void _Rpc24( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[660],
                  0);
    
}


void _Rpc25( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[686],
                  0);
    
}


void _Rpc26( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[712],
                  0);
    
}


void _Rpc27( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[738],
                  0);
    
}


void _Rpc28( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[764],
                  0);
    
}


void _Rpc29( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[790],
                  0);
    
}


void _Rpc30( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[816],
                  0);
    
}


void _Rpc31( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[842],
                  0);
    
}


void _Rpc32( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[868],
                  0);
    
}


void _Rpc33( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[894],
                  0);
    
}


void _Rpc34( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[920],
                  0);
    
}


void _Rpc35( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[946],
                  0);
    
}


void _Rpc36( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[972],
                  0);
    
}


void _Rpc37( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[998],
                  0);
    
}


void _Rpc38( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1024],
                  0);
    
}


void _Rpc39( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1050],
                  0);
    
}


void _Rpc40( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1076],
                  0);
    
}


void _Rpc41( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1102],
                  0);
    
}


void _Rpc42( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1128],
                  0);
    
}


void _Rpc43( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1154],
                  0);
    
}


void _Rpc44( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1180],
                  0);
    
}


void _Rpc45( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1206],
                  0);
    
}


void _Rpc46( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1232],
                  0);
    
}


void _Rpc47( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1258],
                  0);
    
}


void _Rpc48( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1284],
                  0);
    
}


void _Rpc49( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1310],
                  0);
    
}


void _Rpc50( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1336],
                  0);
    
}


void _Rpc51( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1362],
                  0);
    
}


void _Rpc52( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1388],
                  0);
    
}


void _Rpc53( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1414],
                  0);
    
}


void _Rpc54( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1440],
                  0);
    
}


void _Rpc55( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1466],
                  0);
    
}


void _Rpc56( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1492],
                  0);
    
}


void _Rpc57( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1518],
                  0);
    
}


void _Rpc58( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1544],
                  0);
    
}


void _Rpc59( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1570],
                  0);
    
}


void _Rpc60( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1596],
                  0);
    
}


void _Rpc61( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1622],
                  0);
    
}


void _Rpc62( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1648],
                  0);
    
}


void _Rpc63( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1674],
                  0);
    
}


void _Rpc64( void)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1700],
                  0);
    
}


DWORD RpcRemoteFindFirstPrinterChangeNotificationEx( 
    /* [in] */ PRINTER_HANDLE hPrinter,
    /* [in] */ DWORD fdwFlags,
    /* [in] */ DWORD fdwOptions,
    /* [unique][string][in] */ wchar_t *pszLocalMachine,
    /* [in] */ DWORD dwPrinterLocal,
    /* [unique][in] */ RPC_V2_NOTIFY_OPTIONS *pOptions)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&RPRN_StubDesc,
                  (PFORMAT_STRING) &rprn__MIDL_ProcFormatString.Format[1726],
                  hPrinter,
                  fdwFlags,
                  fdwOptions,
                  pszLocalMachine,
                  dwPrinterLocal,
                  pOptions);
    return ( DWORD  )_RetVal.Simple;
    
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

#if !(TARGET_IS_NT50_OR_LATER)
#error You need Windows 2000 or later to run this stub because it uses these features:
#error   /robust command line switch.
#error However, your C/C++ compilation flags indicate you intend to run this app on earlier systems.
#error This app will fail with the RPC_X_WRONG_STUB_VERSION error.
#endif


static const rprn_MIDL_PROC_FORMAT_STRING rprn__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure _Rpc0 */

			0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 10 */	NdrFcShort( 0x0 ),	/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* 0 */
/* 14 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 16 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 18 */	NdrFcShort( 0x0 ),	/* 0 */
/* 20 */	NdrFcShort( 0x0 ),	/* 0 */
/* 22 */	NdrFcShort( 0x0 ),	/* 0 */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcOpenPrinter */

/* 26 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 28 */	NdrFcLong( 0x0 ),	/* 0 */
/* 32 */	NdrFcShort( 0x1 ),	/* 1 */
/* 34 */	NdrFcShort( 0x30 ),	/* x86 Stack size/offset = 48 */
/* 36 */	NdrFcShort( 0x8 ),	/* 8 */
/* 38 */	NdrFcShort( 0x40 ),	/* 64 */
/* 40 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 42 */	0xa,		/* 10 */
			0x5,		/* Ext Flags:  new corr desc, srv corr check, */
/* 44 */	NdrFcShort( 0x0 ),	/* 0 */
/* 46 */	NdrFcShort( 0x1 ),	/* 1 */
/* 48 */	NdrFcShort( 0x0 ),	/* 0 */
/* 50 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter pPrinterName */

/* 52 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 54 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 56 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter pHandle */

/* 58 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 60 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 62 */	NdrFcShort( 0xa ),	/* Type Offset=10 */

	/* Parameter pDatatype */

/* 64 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 66 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 68 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter pDevModeContainer */

/* 70 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 72 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 74 */	NdrFcShort( 0x1e ),	/* Type Offset=30 */

	/* Parameter AccessRequired */

/* 76 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 78 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 80 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 82 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 84 */	NdrFcShort( 0x28 ),	/* x86 Stack size/offset = 40 */
/* 86 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure _Rpc2 */

/* 88 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 90 */	NdrFcLong( 0x0 ),	/* 0 */
/* 94 */	NdrFcShort( 0x2 ),	/* 2 */
/* 96 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 98 */	NdrFcShort( 0x0 ),	/* 0 */
/* 100 */	NdrFcShort( 0x0 ),	/* 0 */
/* 102 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 104 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 106 */	NdrFcShort( 0x0 ),	/* 0 */
/* 108 */	NdrFcShort( 0x0 ),	/* 0 */
/* 110 */	NdrFcShort( 0x0 ),	/* 0 */
/* 112 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc3 */

/* 114 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 116 */	NdrFcLong( 0x0 ),	/* 0 */
/* 120 */	NdrFcShort( 0x3 ),	/* 3 */
/* 122 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 124 */	NdrFcShort( 0x0 ),	/* 0 */
/* 126 */	NdrFcShort( 0x0 ),	/* 0 */
/* 128 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 130 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 132 */	NdrFcShort( 0x0 ),	/* 0 */
/* 134 */	NdrFcShort( 0x0 ),	/* 0 */
/* 136 */	NdrFcShort( 0x0 ),	/* 0 */
/* 138 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc4 */

/* 140 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 142 */	NdrFcLong( 0x0 ),	/* 0 */
/* 146 */	NdrFcShort( 0x4 ),	/* 4 */
/* 148 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 150 */	NdrFcShort( 0x0 ),	/* 0 */
/* 152 */	NdrFcShort( 0x0 ),	/* 0 */
/* 154 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 156 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 158 */	NdrFcShort( 0x0 ),	/* 0 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
/* 162 */	NdrFcShort( 0x0 ),	/* 0 */
/* 164 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc5 */

/* 166 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 168 */	NdrFcLong( 0x0 ),	/* 0 */
/* 172 */	NdrFcShort( 0x5 ),	/* 5 */
/* 174 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 176 */	NdrFcShort( 0x0 ),	/* 0 */
/* 178 */	NdrFcShort( 0x0 ),	/* 0 */
/* 180 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 182 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 184 */	NdrFcShort( 0x0 ),	/* 0 */
/* 186 */	NdrFcShort( 0x0 ),	/* 0 */
/* 188 */	NdrFcShort( 0x0 ),	/* 0 */
/* 190 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc6 */

/* 192 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 194 */	NdrFcLong( 0x0 ),	/* 0 */
/* 198 */	NdrFcShort( 0x6 ),	/* 6 */
/* 200 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 202 */	NdrFcShort( 0x0 ),	/* 0 */
/* 204 */	NdrFcShort( 0x0 ),	/* 0 */
/* 206 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 208 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 210 */	NdrFcShort( 0x0 ),	/* 0 */
/* 212 */	NdrFcShort( 0x0 ),	/* 0 */
/* 214 */	NdrFcShort( 0x0 ),	/* 0 */
/* 216 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc7 */

/* 218 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 220 */	NdrFcLong( 0x0 ),	/* 0 */
/* 224 */	NdrFcShort( 0x7 ),	/* 7 */
/* 226 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 228 */	NdrFcShort( 0x0 ),	/* 0 */
/* 230 */	NdrFcShort( 0x0 ),	/* 0 */
/* 232 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 234 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 236 */	NdrFcShort( 0x0 ),	/* 0 */
/* 238 */	NdrFcShort( 0x0 ),	/* 0 */
/* 240 */	NdrFcShort( 0x0 ),	/* 0 */
/* 242 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc8 */

/* 244 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 246 */	NdrFcLong( 0x0 ),	/* 0 */
/* 250 */	NdrFcShort( 0x8 ),	/* 8 */
/* 252 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 254 */	NdrFcShort( 0x0 ),	/* 0 */
/* 256 */	NdrFcShort( 0x0 ),	/* 0 */
/* 258 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 260 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 262 */	NdrFcShort( 0x0 ),	/* 0 */
/* 264 */	NdrFcShort( 0x0 ),	/* 0 */
/* 266 */	NdrFcShort( 0x0 ),	/* 0 */
/* 268 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc9 */

/* 270 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 272 */	NdrFcLong( 0x0 ),	/* 0 */
/* 276 */	NdrFcShort( 0x9 ),	/* 9 */
/* 278 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 280 */	NdrFcShort( 0x0 ),	/* 0 */
/* 282 */	NdrFcShort( 0x0 ),	/* 0 */
/* 284 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 286 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 288 */	NdrFcShort( 0x0 ),	/* 0 */
/* 290 */	NdrFcShort( 0x0 ),	/* 0 */
/* 292 */	NdrFcShort( 0x0 ),	/* 0 */
/* 294 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc10 */

/* 296 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 298 */	NdrFcLong( 0x0 ),	/* 0 */
/* 302 */	NdrFcShort( 0xa ),	/* 10 */
/* 304 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 306 */	NdrFcShort( 0x0 ),	/* 0 */
/* 308 */	NdrFcShort( 0x0 ),	/* 0 */
/* 310 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 312 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 314 */	NdrFcShort( 0x0 ),	/* 0 */
/* 316 */	NdrFcShort( 0x0 ),	/* 0 */
/* 318 */	NdrFcShort( 0x0 ),	/* 0 */
/* 320 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc11 */

/* 322 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 324 */	NdrFcLong( 0x0 ),	/* 0 */
/* 328 */	NdrFcShort( 0xb ),	/* 11 */
/* 330 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 332 */	NdrFcShort( 0x0 ),	/* 0 */
/* 334 */	NdrFcShort( 0x0 ),	/* 0 */
/* 336 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 338 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 340 */	NdrFcShort( 0x0 ),	/* 0 */
/* 342 */	NdrFcShort( 0x0 ),	/* 0 */
/* 344 */	NdrFcShort( 0x0 ),	/* 0 */
/* 346 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc12 */

/* 348 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 350 */	NdrFcLong( 0x0 ),	/* 0 */
/* 354 */	NdrFcShort( 0xc ),	/* 12 */
/* 356 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 358 */	NdrFcShort( 0x0 ),	/* 0 */
/* 360 */	NdrFcShort( 0x0 ),	/* 0 */
/* 362 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 364 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 366 */	NdrFcShort( 0x0 ),	/* 0 */
/* 368 */	NdrFcShort( 0x0 ),	/* 0 */
/* 370 */	NdrFcShort( 0x0 ),	/* 0 */
/* 372 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc13 */

/* 374 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 376 */	NdrFcLong( 0x0 ),	/* 0 */
/* 380 */	NdrFcShort( 0xd ),	/* 13 */
/* 382 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 384 */	NdrFcShort( 0x0 ),	/* 0 */
/* 386 */	NdrFcShort( 0x0 ),	/* 0 */
/* 388 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 390 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 392 */	NdrFcShort( 0x0 ),	/* 0 */
/* 394 */	NdrFcShort( 0x0 ),	/* 0 */
/* 396 */	NdrFcShort( 0x0 ),	/* 0 */
/* 398 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc14 */

/* 400 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 402 */	NdrFcLong( 0x0 ),	/* 0 */
/* 406 */	NdrFcShort( 0xe ),	/* 14 */
/* 408 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 410 */	NdrFcShort( 0x0 ),	/* 0 */
/* 412 */	NdrFcShort( 0x0 ),	/* 0 */
/* 414 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 416 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 418 */	NdrFcShort( 0x0 ),	/* 0 */
/* 420 */	NdrFcShort( 0x0 ),	/* 0 */
/* 422 */	NdrFcShort( 0x0 ),	/* 0 */
/* 424 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc15 */

/* 426 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 428 */	NdrFcLong( 0x0 ),	/* 0 */
/* 432 */	NdrFcShort( 0xf ),	/* 15 */
/* 434 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 436 */	NdrFcShort( 0x0 ),	/* 0 */
/* 438 */	NdrFcShort( 0x0 ),	/* 0 */
/* 440 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 442 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 444 */	NdrFcShort( 0x0 ),	/* 0 */
/* 446 */	NdrFcShort( 0x0 ),	/* 0 */
/* 448 */	NdrFcShort( 0x0 ),	/* 0 */
/* 450 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc16 */

/* 452 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 454 */	NdrFcLong( 0x0 ),	/* 0 */
/* 458 */	NdrFcShort( 0x10 ),	/* 16 */
/* 460 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 462 */	NdrFcShort( 0x0 ),	/* 0 */
/* 464 */	NdrFcShort( 0x0 ),	/* 0 */
/* 466 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 468 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 470 */	NdrFcShort( 0x0 ),	/* 0 */
/* 472 */	NdrFcShort( 0x0 ),	/* 0 */
/* 474 */	NdrFcShort( 0x0 ),	/* 0 */
/* 476 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc17 */

/* 478 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 480 */	NdrFcLong( 0x0 ),	/* 0 */
/* 484 */	NdrFcShort( 0x11 ),	/* 17 */
/* 486 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 488 */	NdrFcShort( 0x0 ),	/* 0 */
/* 490 */	NdrFcShort( 0x0 ),	/* 0 */
/* 492 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 494 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 496 */	NdrFcShort( 0x0 ),	/* 0 */
/* 498 */	NdrFcShort( 0x0 ),	/* 0 */
/* 500 */	NdrFcShort( 0x0 ),	/* 0 */
/* 502 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc18 */

/* 504 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 506 */	NdrFcLong( 0x0 ),	/* 0 */
/* 510 */	NdrFcShort( 0x12 ),	/* 18 */
/* 512 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 514 */	NdrFcShort( 0x0 ),	/* 0 */
/* 516 */	NdrFcShort( 0x0 ),	/* 0 */
/* 518 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 520 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 522 */	NdrFcShort( 0x0 ),	/* 0 */
/* 524 */	NdrFcShort( 0x0 ),	/* 0 */
/* 526 */	NdrFcShort( 0x0 ),	/* 0 */
/* 528 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc19 */

/* 530 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 532 */	NdrFcLong( 0x0 ),	/* 0 */
/* 536 */	NdrFcShort( 0x13 ),	/* 19 */
/* 538 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 540 */	NdrFcShort( 0x0 ),	/* 0 */
/* 542 */	NdrFcShort( 0x0 ),	/* 0 */
/* 544 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 546 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 548 */	NdrFcShort( 0x0 ),	/* 0 */
/* 550 */	NdrFcShort( 0x0 ),	/* 0 */
/* 552 */	NdrFcShort( 0x0 ),	/* 0 */
/* 554 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc20 */

/* 556 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 558 */	NdrFcLong( 0x0 ),	/* 0 */
/* 562 */	NdrFcShort( 0x14 ),	/* 20 */
/* 564 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 566 */	NdrFcShort( 0x0 ),	/* 0 */
/* 568 */	NdrFcShort( 0x0 ),	/* 0 */
/* 570 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 572 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 574 */	NdrFcShort( 0x0 ),	/* 0 */
/* 576 */	NdrFcShort( 0x0 ),	/* 0 */
/* 578 */	NdrFcShort( 0x0 ),	/* 0 */
/* 580 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc21 */

/* 582 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 584 */	NdrFcLong( 0x0 ),	/* 0 */
/* 588 */	NdrFcShort( 0x15 ),	/* 21 */
/* 590 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 592 */	NdrFcShort( 0x0 ),	/* 0 */
/* 594 */	NdrFcShort( 0x0 ),	/* 0 */
/* 596 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 598 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 600 */	NdrFcShort( 0x0 ),	/* 0 */
/* 602 */	NdrFcShort( 0x0 ),	/* 0 */
/* 604 */	NdrFcShort( 0x0 ),	/* 0 */
/* 606 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc22 */

/* 608 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 610 */	NdrFcLong( 0x0 ),	/* 0 */
/* 614 */	NdrFcShort( 0x16 ),	/* 22 */
/* 616 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 618 */	NdrFcShort( 0x0 ),	/* 0 */
/* 620 */	NdrFcShort( 0x0 ),	/* 0 */
/* 622 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 624 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 626 */	NdrFcShort( 0x0 ),	/* 0 */
/* 628 */	NdrFcShort( 0x0 ),	/* 0 */
/* 630 */	NdrFcShort( 0x0 ),	/* 0 */
/* 632 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc23 */

/* 634 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 636 */	NdrFcLong( 0x0 ),	/* 0 */
/* 640 */	NdrFcShort( 0x17 ),	/* 23 */
/* 642 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 644 */	NdrFcShort( 0x0 ),	/* 0 */
/* 646 */	NdrFcShort( 0x0 ),	/* 0 */
/* 648 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 650 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 652 */	NdrFcShort( 0x0 ),	/* 0 */
/* 654 */	NdrFcShort( 0x0 ),	/* 0 */
/* 656 */	NdrFcShort( 0x0 ),	/* 0 */
/* 658 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc24 */

/* 660 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 662 */	NdrFcLong( 0x0 ),	/* 0 */
/* 666 */	NdrFcShort( 0x18 ),	/* 24 */
/* 668 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 670 */	NdrFcShort( 0x0 ),	/* 0 */
/* 672 */	NdrFcShort( 0x0 ),	/* 0 */
/* 674 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 676 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 678 */	NdrFcShort( 0x0 ),	/* 0 */
/* 680 */	NdrFcShort( 0x0 ),	/* 0 */
/* 682 */	NdrFcShort( 0x0 ),	/* 0 */
/* 684 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc25 */

/* 686 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 688 */	NdrFcLong( 0x0 ),	/* 0 */
/* 692 */	NdrFcShort( 0x19 ),	/* 25 */
/* 694 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 696 */	NdrFcShort( 0x0 ),	/* 0 */
/* 698 */	NdrFcShort( 0x0 ),	/* 0 */
/* 700 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 702 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 704 */	NdrFcShort( 0x0 ),	/* 0 */
/* 706 */	NdrFcShort( 0x0 ),	/* 0 */
/* 708 */	NdrFcShort( 0x0 ),	/* 0 */
/* 710 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc26 */

/* 712 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 714 */	NdrFcLong( 0x0 ),	/* 0 */
/* 718 */	NdrFcShort( 0x1a ),	/* 26 */
/* 720 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 722 */	NdrFcShort( 0x0 ),	/* 0 */
/* 724 */	NdrFcShort( 0x0 ),	/* 0 */
/* 726 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 728 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 730 */	NdrFcShort( 0x0 ),	/* 0 */
/* 732 */	NdrFcShort( 0x0 ),	/* 0 */
/* 734 */	NdrFcShort( 0x0 ),	/* 0 */
/* 736 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc27 */

/* 738 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 740 */	NdrFcLong( 0x0 ),	/* 0 */
/* 744 */	NdrFcShort( 0x1b ),	/* 27 */
/* 746 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 748 */	NdrFcShort( 0x0 ),	/* 0 */
/* 750 */	NdrFcShort( 0x0 ),	/* 0 */
/* 752 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 754 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 756 */	NdrFcShort( 0x0 ),	/* 0 */
/* 758 */	NdrFcShort( 0x0 ),	/* 0 */
/* 760 */	NdrFcShort( 0x0 ),	/* 0 */
/* 762 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc28 */

/* 764 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 766 */	NdrFcLong( 0x0 ),	/* 0 */
/* 770 */	NdrFcShort( 0x1c ),	/* 28 */
/* 772 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 774 */	NdrFcShort( 0x0 ),	/* 0 */
/* 776 */	NdrFcShort( 0x0 ),	/* 0 */
/* 778 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 780 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 782 */	NdrFcShort( 0x0 ),	/* 0 */
/* 784 */	NdrFcShort( 0x0 ),	/* 0 */
/* 786 */	NdrFcShort( 0x0 ),	/* 0 */
/* 788 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc29 */

/* 790 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 792 */	NdrFcLong( 0x0 ),	/* 0 */
/* 796 */	NdrFcShort( 0x1d ),	/* 29 */
/* 798 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 800 */	NdrFcShort( 0x0 ),	/* 0 */
/* 802 */	NdrFcShort( 0x0 ),	/* 0 */
/* 804 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 806 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 808 */	NdrFcShort( 0x0 ),	/* 0 */
/* 810 */	NdrFcShort( 0x0 ),	/* 0 */
/* 812 */	NdrFcShort( 0x0 ),	/* 0 */
/* 814 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc30 */

/* 816 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 818 */	NdrFcLong( 0x0 ),	/* 0 */
/* 822 */	NdrFcShort( 0x1e ),	/* 30 */
/* 824 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 826 */	NdrFcShort( 0x0 ),	/* 0 */
/* 828 */	NdrFcShort( 0x0 ),	/* 0 */
/* 830 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 832 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 834 */	NdrFcShort( 0x0 ),	/* 0 */
/* 836 */	NdrFcShort( 0x0 ),	/* 0 */
/* 838 */	NdrFcShort( 0x0 ),	/* 0 */
/* 840 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc31 */

/* 842 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 844 */	NdrFcLong( 0x0 ),	/* 0 */
/* 848 */	NdrFcShort( 0x1f ),	/* 31 */
/* 850 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 852 */	NdrFcShort( 0x0 ),	/* 0 */
/* 854 */	NdrFcShort( 0x0 ),	/* 0 */
/* 856 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 858 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 860 */	NdrFcShort( 0x0 ),	/* 0 */
/* 862 */	NdrFcShort( 0x0 ),	/* 0 */
/* 864 */	NdrFcShort( 0x0 ),	/* 0 */
/* 866 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc32 */

/* 868 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 870 */	NdrFcLong( 0x0 ),	/* 0 */
/* 874 */	NdrFcShort( 0x20 ),	/* 32 */
/* 876 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 878 */	NdrFcShort( 0x0 ),	/* 0 */
/* 880 */	NdrFcShort( 0x0 ),	/* 0 */
/* 882 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 884 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 886 */	NdrFcShort( 0x0 ),	/* 0 */
/* 888 */	NdrFcShort( 0x0 ),	/* 0 */
/* 890 */	NdrFcShort( 0x0 ),	/* 0 */
/* 892 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc33 */

/* 894 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 896 */	NdrFcLong( 0x0 ),	/* 0 */
/* 900 */	NdrFcShort( 0x21 ),	/* 33 */
/* 902 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 904 */	NdrFcShort( 0x0 ),	/* 0 */
/* 906 */	NdrFcShort( 0x0 ),	/* 0 */
/* 908 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 910 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 912 */	NdrFcShort( 0x0 ),	/* 0 */
/* 914 */	NdrFcShort( 0x0 ),	/* 0 */
/* 916 */	NdrFcShort( 0x0 ),	/* 0 */
/* 918 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc34 */

/* 920 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 922 */	NdrFcLong( 0x0 ),	/* 0 */
/* 926 */	NdrFcShort( 0x22 ),	/* 34 */
/* 928 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 930 */	NdrFcShort( 0x0 ),	/* 0 */
/* 932 */	NdrFcShort( 0x0 ),	/* 0 */
/* 934 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 936 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 938 */	NdrFcShort( 0x0 ),	/* 0 */
/* 940 */	NdrFcShort( 0x0 ),	/* 0 */
/* 942 */	NdrFcShort( 0x0 ),	/* 0 */
/* 944 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc35 */

/* 946 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 948 */	NdrFcLong( 0x0 ),	/* 0 */
/* 952 */	NdrFcShort( 0x23 ),	/* 35 */
/* 954 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 956 */	NdrFcShort( 0x0 ),	/* 0 */
/* 958 */	NdrFcShort( 0x0 ),	/* 0 */
/* 960 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 962 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 964 */	NdrFcShort( 0x0 ),	/* 0 */
/* 966 */	NdrFcShort( 0x0 ),	/* 0 */
/* 968 */	NdrFcShort( 0x0 ),	/* 0 */
/* 970 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc36 */

/* 972 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 974 */	NdrFcLong( 0x0 ),	/* 0 */
/* 978 */	NdrFcShort( 0x24 ),	/* 36 */
/* 980 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 982 */	NdrFcShort( 0x0 ),	/* 0 */
/* 984 */	NdrFcShort( 0x0 ),	/* 0 */
/* 986 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 988 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 990 */	NdrFcShort( 0x0 ),	/* 0 */
/* 992 */	NdrFcShort( 0x0 ),	/* 0 */
/* 994 */	NdrFcShort( 0x0 ),	/* 0 */
/* 996 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc37 */

/* 998 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1000 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1004 */	NdrFcShort( 0x25 ),	/* 37 */
/* 1006 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1008 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1010 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1012 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1014 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1016 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1018 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1020 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1022 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc38 */

/* 1024 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1026 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1030 */	NdrFcShort( 0x26 ),	/* 38 */
/* 1032 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1034 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1036 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1038 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1040 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1042 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1044 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1046 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1048 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc39 */

/* 1050 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1052 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1056 */	NdrFcShort( 0x27 ),	/* 39 */
/* 1058 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1060 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1062 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1064 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1066 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1068 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1070 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1072 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1074 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc40 */

/* 1076 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1078 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1082 */	NdrFcShort( 0x28 ),	/* 40 */
/* 1084 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1086 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1088 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1090 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1092 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1094 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1096 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1098 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1100 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc41 */

/* 1102 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1104 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1108 */	NdrFcShort( 0x29 ),	/* 41 */
/* 1110 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1112 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1114 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1116 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1118 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1120 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1122 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1124 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1126 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc42 */

/* 1128 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1130 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1134 */	NdrFcShort( 0x2a ),	/* 42 */
/* 1136 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1138 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1140 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1142 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1144 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1146 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1148 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1150 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1152 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc43 */

/* 1154 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1156 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1160 */	NdrFcShort( 0x2b ),	/* 43 */
/* 1162 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1164 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1166 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1168 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1170 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1172 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1174 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1176 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1178 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc44 */

/* 1180 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1182 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1186 */	NdrFcShort( 0x2c ),	/* 44 */
/* 1188 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1190 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1192 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1194 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1196 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1198 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1200 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1202 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1204 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc45 */

/* 1206 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1208 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1212 */	NdrFcShort( 0x2d ),	/* 45 */
/* 1214 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1218 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1220 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1222 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1224 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1226 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1228 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1230 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc46 */

/* 1232 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1234 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1238 */	NdrFcShort( 0x2e ),	/* 46 */
/* 1240 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1242 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1244 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1246 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1248 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1250 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1252 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1254 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1256 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc47 */

/* 1258 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1260 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1264 */	NdrFcShort( 0x2f ),	/* 47 */
/* 1266 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1268 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1270 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1272 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1274 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1276 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1278 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1280 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1282 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc48 */

/* 1284 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1286 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1290 */	NdrFcShort( 0x30 ),	/* 48 */
/* 1292 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1294 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1296 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1298 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1300 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1302 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1304 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1306 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1308 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc49 */

/* 1310 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1312 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1316 */	NdrFcShort( 0x31 ),	/* 49 */
/* 1318 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1320 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1322 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1324 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1326 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1328 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1330 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1332 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1334 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc50 */

/* 1336 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1338 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1342 */	NdrFcShort( 0x32 ),	/* 50 */
/* 1344 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1346 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1348 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1350 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1352 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1354 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1356 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1358 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1360 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc51 */

/* 1362 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1364 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1368 */	NdrFcShort( 0x33 ),	/* 51 */
/* 1370 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1372 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1374 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1376 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1378 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1380 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1382 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1384 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1386 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc52 */

/* 1388 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1390 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1394 */	NdrFcShort( 0x34 ),	/* 52 */
/* 1396 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1398 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1400 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1402 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1404 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1406 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1408 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1410 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1412 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc53 */

/* 1414 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1416 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1420 */	NdrFcShort( 0x35 ),	/* 53 */
/* 1422 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1424 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1426 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1428 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1430 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1432 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1434 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1436 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1438 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc54 */

/* 1440 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1442 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1446 */	NdrFcShort( 0x36 ),	/* 54 */
/* 1448 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1450 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1452 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1454 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1456 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1458 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1460 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1462 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1464 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc55 */

/* 1466 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1468 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1472 */	NdrFcShort( 0x37 ),	/* 55 */
/* 1474 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1476 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1478 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1480 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1482 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1484 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1486 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1488 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1490 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc56 */

/* 1492 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1494 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1498 */	NdrFcShort( 0x38 ),	/* 56 */
/* 1500 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1502 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1504 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1506 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1508 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1510 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1512 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1514 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1516 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc57 */

/* 1518 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1520 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1524 */	NdrFcShort( 0x39 ),	/* 57 */
/* 1526 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1528 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1530 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1532 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1534 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1536 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1538 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1540 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1542 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc58 */

/* 1544 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1546 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1550 */	NdrFcShort( 0x3a ),	/* 58 */
/* 1552 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1554 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1556 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1558 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1560 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1562 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1564 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1566 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1568 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc59 */

/* 1570 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1572 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1576 */	NdrFcShort( 0x3b ),	/* 59 */
/* 1578 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1580 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1582 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1584 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1586 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1588 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1590 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1592 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1594 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc60 */

/* 1596 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1598 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1602 */	NdrFcShort( 0x3c ),	/* 60 */
/* 1604 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1606 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1608 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1610 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1612 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1614 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1616 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1618 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1620 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc61 */

/* 1622 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1624 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1628 */	NdrFcShort( 0x3d ),	/* 61 */
/* 1630 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1632 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1634 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1636 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1638 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1640 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1642 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1644 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1646 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc62 */

/* 1648 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1650 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1654 */	NdrFcShort( 0x3e ),	/* 62 */
/* 1656 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1658 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1660 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1662 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1664 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1666 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1668 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1670 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1672 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc63 */

/* 1674 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1676 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1680 */	NdrFcShort( 0x3f ),	/* 63 */
/* 1682 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1684 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1686 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1688 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1690 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1692 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1694 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1696 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1698 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Rpc64 */

/* 1700 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x48,		/* Old Flags:  */
/* 1702 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1706 */	NdrFcShort( 0x40 ),	/* 64 */
/* 1708 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1710 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1712 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1714 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 1716 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 1718 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1720 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1722 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1724 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure RpcRemoteFindFirstPrinterChangeNotificationEx */

/* 1726 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 1728 */	NdrFcLong( 0x0 ),	/* 0 */
/* 1732 */	NdrFcShort( 0x41 ),	/* 65 */
/* 1734 */	NdrFcShort( 0x38 ),	/* x86 Stack size/offset = 56 */
/* 1736 */	0x30,		/* FC_BIND_CONTEXT */
			0x40,		/* Ctxt flags:  in, */
/* 1738 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1740 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 1742 */	NdrFcShort( 0x3c ),	/* 60 */
/* 1744 */	NdrFcShort( 0x8 ),	/* 8 */
/* 1746 */	0x46,		/* Oi2 Flags:  clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 1748 */	0xa,		/* 10 */
			0x5,		/* Ext Flags:  new corr desc, srv corr check, */
/* 1750 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1752 */	NdrFcShort( 0x1 ),	/* 1 */
/* 1754 */	NdrFcShort( 0x0 ),	/* 0 */
/* 1756 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter hPrinter */

/* 1758 */	NdrFcShort( 0x8 ),	/* Flags:  in, */
/* 1760 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 1762 */	NdrFcShort( 0x2e ),	/* Type Offset=46 */

	/* Parameter fdwFlags */

/* 1764 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 1766 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 1768 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter fdwOptions */

/* 1770 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 1772 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 1774 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pszLocalMachine */

/* 1776 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 1778 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 1780 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter dwPrinterLocal */

/* 1782 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 1784 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 1786 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pOptions */

/* 1788 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 1790 */	NdrFcShort( 0x28 ),	/* x86 Stack size/offset = 40 */
/* 1792 */	NdrFcShort( 0x32 ),	/* Type Offset=50 */

	/* Return value */

/* 1794 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 1796 */	NdrFcShort( 0x30 ),	/* x86 Stack size/offset = 48 */
/* 1798 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const rprn_MIDL_TYPE_FORMAT_STRING rprn__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/*  4 */	
			0x25,		/* FC_C_WSTRING */
			0x5c,		/* FC_PAD */
/*  6 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/*  8 */	NdrFcShort( 0x2 ),	/* Offset= 2 (10) */
/* 10 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 12 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 14 */	
			0x11, 0x0,	/* FC_RP */
/* 16 */	NdrFcShort( 0xe ),	/* Offset= 14 (30) */
/* 18 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 20 */	NdrFcShort( 0x1 ),	/* 1 */
/* 22 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 24 */	NdrFcShort( 0x0 ),	/* 0 */
/* 26 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 28 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 30 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 32 */	NdrFcShort( 0x10 ),	/* 16 */
/* 34 */	NdrFcShort( 0x0 ),	/* 0 */
/* 36 */	NdrFcShort( 0x6 ),	/* Offset= 6 (42) */
/* 38 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 40 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 42 */	
			0x12, 0x0,	/* FC_UP */
/* 44 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (18) */
/* 46 */	0x30,		/* FC_BIND_CONTEXT */
			0x41,		/* Ctxt flags:  in, can't be null */
/* 48 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 50 */	
			0x12, 0x0,	/* FC_UP */
/* 52 */	NdrFcShort( 0x38 ),	/* Offset= 56 (108) */
/* 54 */	
			0x1b,		/* FC_CARRAY */
			0x1,		/* 1 */
/* 56 */	NdrFcShort( 0x2 ),	/* 2 */
/* 58 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 60 */	NdrFcShort( 0xc ),	/* 12 */
/* 62 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 64 */	0x6,		/* FC_SHORT */
			0x5b,		/* FC_END */
/* 66 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 68 */	NdrFcShort( 0x18 ),	/* 24 */
/* 70 */	NdrFcShort( 0x0 ),	/* 0 */
/* 72 */	NdrFcShort( 0xa ),	/* Offset= 10 (82) */
/* 74 */	0x6,		/* FC_SHORT */
			0x6,		/* FC_SHORT */
/* 76 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 78 */	0x8,		/* FC_LONG */
			0x36,		/* FC_POINTER */
/* 80 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 82 */	
			0x12, 0x0,	/* FC_UP */
/* 84 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (54) */
/* 86 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 88 */	NdrFcShort( 0x0 ),	/* 0 */
/* 90 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 92 */	NdrFcShort( 0x8 ),	/* 8 */
/* 94 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 96 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 100 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 102 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 104 */	NdrFcShort( 0xffda ),	/* Offset= -38 (66) */
/* 106 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 108 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 110 */	NdrFcShort( 0x18 ),	/* 24 */
/* 112 */	NdrFcShort( 0x0 ),	/* 0 */
/* 114 */	NdrFcShort( 0x8 ),	/* Offset= 8 (122) */
/* 116 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 118 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 120 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 122 */	
			0x12, 0x0,	/* FC_UP */
/* 124 */	NdrFcShort( 0xffda ),	/* Offset= -38 (86) */

			0x0
        }
    };

static const unsigned short RPRN_FormatStringOffsetTable[] =
    {
    0,
    26,
    88,
    114,
    140,
    166,
    192,
    218,
    244,
    270,
    296,
    322,
    348,
    374,
    400,
    426,
    452,
    478,
    504,
    530,
    556,
    582,
    608,
    634,
    660,
    686,
    712,
    738,
    764,
    790,
    816,
    842,
    868,
    894,
    920,
    946,
    972,
    998,
    1024,
    1050,
    1076,
    1102,
    1128,
    1154,
    1180,
    1206,
    1232,
    1258,
    1284,
    1310,
    1336,
    1362,
    1388,
    1414,
    1440,
    1466,
    1492,
    1518,
    1544,
    1570,
    1596,
    1622,
    1648,
    1674,
    1700,
    1726
    };


#ifdef __cplusplus
namespace {
#endif
static const MIDL_STUB_DESC RPRN_StubDesc = 
    {
    (void *)& RPRN___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &hRprnBinding,
    0,
    0,
    0,
    0,
    rprn__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x50002, /* Ndr library version */
    0,
    0x8010274, /* MIDL Version 8.1.628 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x1, /* MIDL flag */
    0, /* cs routines */
    0,   /* proxy/server info */
    0
    };
#ifdef __cplusplus
}
#endif
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/

