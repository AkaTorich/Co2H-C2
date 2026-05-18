

/* this ALWAYS GENERATED file contains the RPC client stubs */


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

#include "drsuapi.h"

#define TYPE_FORMAT_STRING_SIZE   635                               
#define PROC_FORMAT_STRING_SIZE   233                               
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _drsuapi_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } drsuapi_MIDL_TYPE_FORMAT_STRING;

typedef struct _drsuapi_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } drsuapi_MIDL_PROC_FORMAT_STRING;

typedef struct _drsuapi_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } drsuapi_MIDL_EXPR_FORMAT_STRING;


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


extern const drsuapi_MIDL_TYPE_FORMAT_STRING drsuapi__MIDL_TypeFormatString;
extern const drsuapi_MIDL_PROC_FORMAT_STRING drsuapi__MIDL_ProcFormatString;
extern const drsuapi_MIDL_EXPR_FORMAT_STRING drsuapi__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: __MIDL_itf_drsuapi_0000_0000, ver. 0.0,
   GUID={0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}} */


/* Standard interface: drsuapi, ver. 4.0,
   GUID={0xe3514235,0x4b06,0x11d1,{0xab,0x04,0x00,0xc0,0x4f,0xc2,0xdc,0xd2}} */



static const RPC_CLIENT_INTERFACE drsuapi___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0xe3514235,0x4b06,0x11d1,{0xab,0x04,0x00,0xc0,0x4f,0xc2,0xdc,0xd2}},{4,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE drsuapi_v4_0_c_ifspec = (RPC_IF_HANDLE)& drsuapi___RpcClientInterface;
#ifdef __cplusplus
namespace {
#endif

extern const MIDL_STUB_DESC drsuapi_StubDesc;
#ifdef __cplusplus
}
#endif

static RPC_BINDING_HANDLE drsuapi__MIDL_AutoBindHandle;


ULONG IDL_DRSBind( 
    /* [in] */ handle_t rpc_handle,
    /* [unique][in] */ GUID *puuidClientDsa,
    /* [unique][in] */ DRS_EXTENSIONS *pextClient,
    /* [out] */ DRS_EXTENSIONS **ppextServer,
    /* [ref][out] */ DRS_HANDLE *phDrs)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&drsuapi_StubDesc,
                  (PFORMAT_STRING) &drsuapi__MIDL_ProcFormatString.Format[0],
                  rpc_handle,
                  puuidClientDsa,
                  pextClient,
                  ppextServer,
                  phDrs);
    return ( ULONG  )_RetVal.Simple;
    
}


void _Opnum1( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&drsuapi_StubDesc,
                  (PFORMAT_STRING) &drsuapi__MIDL_ProcFormatString.Format[60],
                  IDL_handle);
    
}


void _Opnum2( 
    /* [in] */ handle_t IDL_handle)
{

    NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&drsuapi_StubDesc,
                  (PFORMAT_STRING) &drsuapi__MIDL_ProcFormatString.Format[90],
                  IDL_handle);
    
}


ULONG IDL_DRSGetNCChanges( 
    /* [ref][in] */ DRS_HANDLE *phDrs,
    /* [in] */ DWORD dwInVersion,
    /* [switch_is][in] */ DRS_MSG_GETCHGREQ *pmsgIn,
    /* [ref][out] */ DWORD *pdwOutVersion,
    /* [switch_is][ref][out] */ DRS_MSG_GETCHGREPLY *pmsgOut)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&drsuapi_StubDesc,
                  (PFORMAT_STRING) &drsuapi__MIDL_ProcFormatString.Format[120],
                  phDrs,
                  dwInVersion,
                  pmsgIn,
                  pdwOutVersion,
                  pmsgOut);
    return ( ULONG  )_RetVal.Simple;
    
}


ULONG IDL_DRSUnbind( 
    /* [ref][out][in] */ DRS_HANDLE *phDrs)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&drsuapi_StubDesc,
                  (PFORMAT_STRING) &drsuapi__MIDL_ProcFormatString.Format[188],
                  phDrs);
    return ( ULONG  )_RetVal.Simple;
    
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


static const drsuapi_MIDL_PROC_FORMAT_STRING drsuapi__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure IDL_DRSBind */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x30 ),	/* x86 Stack size/offset = 48 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x44 ),	/* 68 */
/* 16 */	NdrFcShort( 0x40 ),	/* 64 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x5,		/* 5 */
/* 20 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter puuidClientDsa */

/* 30 */	NdrFcShort( 0xa ),	/* Flags:  must free, in, */
/* 32 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 34 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter pextClient */

/* 36 */	NdrFcShort( 0xb ),	/* Flags:  must size, must free, in, */
/* 38 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 40 */	NdrFcShort( 0x18 ),	/* Type Offset=24 */

	/* Parameter ppextServer */

/* 42 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 44 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 46 */	NdrFcShort( 0x38 ),	/* Type Offset=56 */

	/* Parameter phDrs */

/* 48 */	NdrFcShort( 0x110 ),	/* Flags:  out, simple ref, */
/* 50 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 52 */	NdrFcShort( 0x40 ),	/* Type Offset=64 */

	/* Return value */

/* 54 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 56 */	NdrFcShort( 0x28 ),	/* x86 Stack size/offset = 40 */
/* 58 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure _Opnum1 */

/* 60 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 62 */	NdrFcLong( 0x0 ),	/* 0 */
/* 66 */	NdrFcShort( 0x1 ),	/* 1 */
/* 68 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 70 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 72 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 74 */	NdrFcShort( 0x0 ),	/* 0 */
/* 76 */	NdrFcShort( 0x0 ),	/* 0 */
/* 78 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 80 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 82 */	NdrFcShort( 0x0 ),	/* 0 */
/* 84 */	NdrFcShort( 0x0 ),	/* 0 */
/* 86 */	NdrFcShort( 0x0 ),	/* 0 */
/* 88 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure _Opnum2 */

/* 90 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 92 */	NdrFcLong( 0x0 ),	/* 0 */
/* 96 */	NdrFcShort( 0x2 ),	/* 2 */
/* 98 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 100 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 102 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 104 */	NdrFcShort( 0x0 ),	/* 0 */
/* 106 */	NdrFcShort( 0x0 ),	/* 0 */
/* 108 */	0x40,		/* Oi2 Flags:  has ext, */
			0x0,		/* 0 */
/* 110 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 112 */	NdrFcShort( 0x0 ),	/* 0 */
/* 114 */	NdrFcShort( 0x0 ),	/* 0 */
/* 116 */	NdrFcShort( 0x0 ),	/* 0 */
/* 118 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Procedure IDL_DRSGetNCChanges */

/* 120 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 122 */	NdrFcLong( 0x0 ),	/* 0 */
/* 126 */	NdrFcShort( 0x3 ),	/* 3 */
/* 128 */	NdrFcShort( 0x30 ),	/* x86 Stack size/offset = 48 */
/* 130 */	0x30,		/* FC_BIND_CONTEXT */
			0xc0,		/* Ctxt flags:  via ptr, in, */
/* 132 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 134 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 136 */	NdrFcShort( 0x40 ),	/* 64 */
/* 138 */	NdrFcShort( 0x24 ),	/* 36 */
/* 140 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x6,		/* 6 */
/* 142 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 144 */	NdrFcShort( 0x1 ),	/* 1 */
/* 146 */	NdrFcShort( 0x1 ),	/* 1 */
/* 148 */	NdrFcShort( 0x0 ),	/* 0 */
/* 150 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter phDrs */

/* 152 */	NdrFcShort( 0x108 ),	/* Flags:  in, simple ref, */
/* 154 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 156 */	NdrFcShort( 0x48 ),	/* Type Offset=72 */

	/* Parameter dwInVersion */

/* 158 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 160 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 162 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pmsgIn */

/* 164 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 166 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 168 */	NdrFcShort( 0x50 ),	/* Type Offset=80 */

	/* Parameter pdwOutVersion */

/* 170 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 172 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 174 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter pmsgOut */

/* 176 */	NdrFcShort( 0x113 ),	/* Flags:  must size, must free, out, simple ref, */
/* 178 */	NdrFcShort( 0x20 ),	/* x86 Stack size/offset = 32 */
/* 180 */	NdrFcShort( 0x160 ),	/* Type Offset=352 */

	/* Return value */

/* 182 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 184 */	NdrFcShort( 0x28 ),	/* x86 Stack size/offset = 40 */
/* 186 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Procedure IDL_DRSUnbind */

/* 188 */	0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/* 190 */	NdrFcLong( 0x0 ),	/* 0 */
/* 194 */	NdrFcShort( 0x4 ),	/* 4 */
/* 196 */	NdrFcShort( 0x10 ),	/* x86 Stack size/offset = 16 */
/* 198 */	0x30,		/* FC_BIND_CONTEXT */
			0xe0,		/* Ctxt flags:  via ptr, in, out, */
/* 200 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 202 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 204 */	NdrFcShort( 0x38 ),	/* 56 */
/* 206 */	NdrFcShort( 0x40 ),	/* 64 */
/* 208 */	0x44,		/* Oi2 Flags:  has return, has ext, */
			0x2,		/* 2 */
/* 210 */	0xa,		/* 10 */
			0x1,		/* Ext Flags:  new corr desc, */
/* 212 */	NdrFcShort( 0x0 ),	/* 0 */
/* 214 */	NdrFcShort( 0x0 ),	/* 0 */
/* 216 */	NdrFcShort( 0x0 ),	/* 0 */
/* 218 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter phDrs */

/* 220 */	NdrFcShort( 0x118 ),	/* Flags:  in, out, simple ref, */
/* 222 */	NdrFcShort( 0x0 ),	/* x86 Stack size/offset = 0 */
/* 224 */	NdrFcShort( 0x276 ),	/* Type Offset=630 */

	/* Return value */

/* 226 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 228 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 230 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const drsuapi_MIDL_TYPE_FORMAT_STRING drsuapi__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x12, 0x0,	/* FC_UP */
/*  4 */	NdrFcShort( 0x8 ),	/* Offset= 8 (12) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 14 */	NdrFcShort( 0x10 ),	/* 16 */
/* 16 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 18 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 20 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (6) */
			0x5b,		/* FC_END */
/* 24 */	
			0x12, 0x0,	/* FC_UP */
/* 26 */	NdrFcShort( 0xe ),	/* Offset= 14 (40) */
/* 28 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 30 */	NdrFcShort( 0x1 ),	/* 1 */
/* 32 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 34 */	NdrFcShort( 0x0 ),	/* 0 */
/* 36 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 38 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 40 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 42 */	NdrFcShort( 0x10 ),	/* 16 */
/* 44 */	NdrFcShort( 0x0 ),	/* 0 */
/* 46 */	NdrFcShort( 0x6 ),	/* Offset= 6 (52) */
/* 48 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 50 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 52 */	
			0x12, 0x0,	/* FC_UP */
/* 54 */	NdrFcShort( 0xffe6 ),	/* Offset= -26 (28) */
/* 56 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 58 */	NdrFcShort( 0xffde ),	/* Offset= -34 (24) */
/* 60 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 62 */	NdrFcShort( 0x2 ),	/* Offset= 2 (64) */
/* 64 */	0x30,		/* FC_BIND_CONTEXT */
			0xa0,		/* Ctxt flags:  via ptr, out, */
/* 66 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 68 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 70 */	NdrFcShort( 0x2 ),	/* Offset= 2 (72) */
/* 72 */	0x30,		/* FC_BIND_CONTEXT */
			0xc1,		/* Ctxt flags:  via ptr, in, can't be null */
/* 74 */	0x0,		/* 0 */
			0x0,		/* 0 */
/* 76 */	
			0x11, 0x0,	/* FC_RP */
/* 78 */	NdrFcShort( 0x2 ),	/* Offset= 2 (80) */
/* 80 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 82 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 84 */	NdrFcShort( 0x8 ),	/* x86 Stack size/offset = 8 */
/* 86 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 88 */	NdrFcShort( 0x2 ),	/* Offset= 2 (90) */
/* 90 */	NdrFcShort( 0x68 ),	/* 104 */
/* 92 */	NdrFcShort( 0x1 ),	/* 1 */
/* 94 */	NdrFcLong( 0x8 ),	/* 8 */
/* 98 */	NdrFcShort( 0xc8 ),	/* Offset= 200 (298) */
/* 100 */	NdrFcShort( 0xffff ),	/* Offset= -1 (99) */
/* 102 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 104 */	NdrFcShort( 0x10 ),	/* 16 */
/* 106 */	NdrFcShort( 0x0 ),	/* 0 */
/* 108 */	NdrFcShort( 0x6 ),	/* Offset= 6 (114) */
/* 110 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 112 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 114 */	
			0x12, 0x0,	/* FC_UP */
/* 116 */	NdrFcShort( 0xffa8 ),	/* Offset= -88 (28) */
/* 118 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 120 */	NdrFcShort( 0x18 ),	/* 24 */
/* 122 */	NdrFcShort( 0x0 ),	/* 0 */
/* 124 */	NdrFcShort( 0x0 ),	/* Offset= 0 (124) */
/* 126 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 128 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 130 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (102) */
/* 132 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 134 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 136 */	NdrFcShort( 0x0 ),	/* 0 */
/* 138 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 140 */	NdrFcShort( 0x0 ),	/* 0 */
/* 142 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 144 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 148 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 150 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 152 */	NdrFcShort( 0xffde ),	/* Offset= -34 (118) */
/* 154 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 156 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 158 */	NdrFcShort( 0x10 ),	/* 16 */
/* 160 */	NdrFcShort( 0x0 ),	/* 0 */
/* 162 */	NdrFcShort( 0x6 ),	/* Offset= 6 (168) */
/* 164 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 166 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 168 */	
			0x12, 0x0,	/* FC_UP */
/* 170 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (134) */
/* 172 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/* 174 */	NdrFcShort( 0x1c ),	/* 28 */
/* 176 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 178 */	
			0x1b,		/* FC_CARRAY */
			0x1,		/* 1 */
/* 180 */	NdrFcShort( 0x2 ),	/* 2 */
/* 182 */	0x17,		/* Corr desc:  field pointer, FC_USHORT */
			0x57,		/* FC_ADD_1 */
/* 184 */	NdrFcShort( 0x34 ),	/* 52 */
/* 186 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 188 */	0x5,		/* FC_WCHAR */
			0x5b,		/* FC_END */
/* 190 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 192 */	NdrFcShort( 0x40 ),	/* 64 */
/* 194 */	NdrFcShort( 0x0 ),	/* 0 */
/* 196 */	NdrFcShort( 0x10 ),	/* Offset= 16 (212) */
/* 198 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 200 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 202 */	NdrFcShort( 0xff42 ),	/* Offset= -190 (12) */
/* 204 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 206 */	NdrFcShort( 0xffde ),	/* Offset= -34 (172) */
/* 208 */	0x6,		/* FC_SHORT */
			0x3e,		/* FC_STRUCTPAD2 */
/* 210 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 212 */	
			0x12, 0x0,	/* FC_UP */
/* 214 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (178) */
/* 216 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 218 */	NdrFcShort( 0x18 ),	/* 24 */
/* 220 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 222 */	NdrFcShort( 0xff2e ),	/* Offset= -210 (12) */
/* 224 */	0xb,		/* FC_HYPER */
			0x5b,		/* FC_END */
/* 226 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 228 */	NdrFcShort( 0x0 ),	/* 0 */
/* 230 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 232 */	NdrFcShort( 0x10 ),	/* 16 */
/* 234 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 236 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 240 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 242 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 244 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (216) */
/* 246 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 248 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 250 */	NdrFcShort( 0x20 ),	/* 32 */
/* 252 */	NdrFcShort( 0x0 ),	/* 0 */
/* 254 */	NdrFcShort( 0xa ),	/* Offset= 10 (264) */
/* 256 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 258 */	0xb,		/* FC_HYPER */
			0x8,		/* FC_LONG */
/* 260 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 262 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 264 */	
			0x12, 0x0,	/* FC_UP */
/* 266 */	NdrFcShort( 0xffd8 ),	/* Offset= -40 (226) */
/* 268 */	
			0x1b,		/* FC_CARRAY */
			0x3,		/* 3 */
/* 270 */	NdrFcShort( 0x4 ),	/* 4 */
/* 272 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 274 */	NdrFcShort( 0x8 ),	/* 8 */
/* 276 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 278 */	0x8,		/* FC_LONG */
			0x5b,		/* FC_END */
/* 280 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 282 */	NdrFcShort( 0x18 ),	/* 24 */
/* 284 */	NdrFcShort( 0x0 ),	/* 0 */
/* 286 */	NdrFcShort( 0x8 ),	/* Offset= 8 (294) */
/* 288 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 290 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 292 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 294 */	
			0x12, 0x0,	/* FC_UP */
/* 296 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (268) */
/* 298 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 300 */	NdrFcShort( 0x68 ),	/* 104 */
/* 302 */	NdrFcShort( 0x0 ),	/* 0 */
/* 304 */	NdrFcShort( 0x18 ),	/* Offset= 24 (328) */
/* 306 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 308 */	NdrFcShort( 0xfed8 ),	/* Offset= -296 (12) */
/* 310 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 312 */	NdrFcShort( 0xfed4 ),	/* Offset= -300 (12) */
/* 314 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 316 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 318 */	NdrFcShort( 0xff5e ),	/* Offset= -162 (156) */
/* 320 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 322 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 324 */	0xb,		/* FC_HYPER */
			0x36,		/* FC_POINTER */
/* 326 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 328 */	
			0x12, 0x0,	/* FC_UP */
/* 330 */	NdrFcShort( 0xff74 ),	/* Offset= -140 (190) */
/* 332 */	
			0x12, 0x0,	/* FC_UP */
/* 334 */	NdrFcShort( 0xffaa ),	/* Offset= -86 (248) */
/* 336 */	
			0x12, 0x0,	/* FC_UP */
/* 338 */	NdrFcShort( 0xffc6 ),	/* Offset= -58 (280) */
/* 340 */	
			0x12, 0x0,	/* FC_UP */
/* 342 */	NdrFcShort( 0xffc2 ),	/* Offset= -62 (280) */
/* 344 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 346 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */
/* 348 */	
			0x11, 0x0,	/* FC_RP */
/* 350 */	NdrFcShort( 0x2 ),	/* Offset= 2 (352) */
/* 352 */	
			0x2b,		/* FC_NON_ENCAPSULATED_UNION */
			0x9,		/* FC_ULONG */
/* 354 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 356 */	NdrFcShort( 0x18 ),	/* x86 Stack size/offset = 24 */
/* 358 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 360 */	NdrFcShort( 0x2 ),	/* Offset= 2 (362) */
/* 362 */	NdrFcShort( 0x78 ),	/* 120 */
/* 364 */	NdrFcShort( 0x1 ),	/* 1 */
/* 366 */	NdrFcLong( 0x6 ),	/* 6 */
/* 370 */	NdrFcShort( 0xd0 ),	/* Offset= 208 (578) */
/* 372 */	NdrFcShort( 0xffff ),	/* Offset= -1 (371) */
/* 374 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 376 */	NdrFcShort( 0x10 ),	/* 16 */
/* 378 */	NdrFcShort( 0x0 ),	/* 0 */
/* 380 */	NdrFcShort( 0x6 ),	/* Offset= 6 (386) */
/* 382 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 384 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 386 */	
			0x12, 0x0,	/* FC_UP */
/* 388 */	NdrFcShort( 0xfe98 ),	/* Offset= -360 (28) */
/* 390 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 392 */	NdrFcShort( 0x0 ),	/* 0 */
/* 394 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 396 */	NdrFcShort( 0x0 ),	/* 0 */
/* 398 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 400 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 404 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 406 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 408 */	NdrFcShort( 0xffde ),	/* Offset= -34 (374) */
/* 410 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 412 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 414 */	NdrFcShort( 0x10 ),	/* 16 */
/* 416 */	NdrFcShort( 0x0 ),	/* 0 */
/* 418 */	NdrFcShort( 0x6 ),	/* Offset= 6 (424) */
/* 420 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 422 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 424 */	
			0x12, 0x0,	/* FC_UP */
/* 426 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (390) */
/* 428 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 430 */	NdrFcShort( 0x18 ),	/* 24 */
/* 432 */	NdrFcShort( 0x0 ),	/* 0 */
/* 434 */	NdrFcShort( 0x0 ),	/* Offset= 0 (434) */
/* 436 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 438 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 440 */	NdrFcShort( 0xffe4 ),	/* Offset= -28 (412) */
/* 442 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 444 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x3,		/* 3 */
/* 446 */	NdrFcShort( 0x0 ),	/* 0 */
/* 448 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 450 */	NdrFcShort( 0x0 ),	/* 0 */
/* 452 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 454 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 458 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 460 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 462 */	NdrFcShort( 0xffde ),	/* Offset= -34 (428) */
/* 464 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 466 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 468 */	NdrFcShort( 0x10 ),	/* 16 */
/* 470 */	NdrFcShort( 0x0 ),	/* 0 */
/* 472 */	NdrFcShort( 0x6 ),	/* Offset= 6 (478) */
/* 474 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 476 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 478 */	
			0x12, 0x0,	/* FC_UP */
/* 480 */	NdrFcShort( 0xffdc ),	/* Offset= -36 (444) */
/* 482 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 484 */	NdrFcShort( 0x20 ),	/* 32 */
/* 486 */	NdrFcShort( 0x0 ),	/* 0 */
/* 488 */	NdrFcShort( 0xa ),	/* Offset= 10 (498) */
/* 490 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 492 */	0x40,		/* FC_STRUCTPAD4 */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 494 */	0x0,		/* 0 */
			NdrFcShort( 0xffe3 ),	/* Offset= -29 (466) */
			0x5b,		/* FC_END */
/* 498 */	
			0x12, 0x0,	/* FC_UP */
/* 500 */	NdrFcShort( 0xfeca ),	/* Offset= -310 (190) */
/* 502 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 504 */	NdrFcShort( 0x30 ),	/* 48 */
/* 506 */	NdrFcShort( 0x0 ),	/* 0 */
/* 508 */	NdrFcShort( 0xa ),	/* Offset= 10 (518) */
/* 510 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 512 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (482) */
/* 514 */	0x36,		/* FC_POINTER */
			0x36,		/* FC_POINTER */
/* 516 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 518 */	
			0x12, 0x0,	/* FC_UP */
/* 520 */	NdrFcShort( 0xffee ),	/* Offset= -18 (502) */
/* 522 */	
			0x12, 0x8,	/* FC_UP [simple_pointer] */
/* 524 */	0x1,		/* FC_BYTE */
			0x5c,		/* FC_PAD */
/* 526 */	
			0x15,		/* FC_STRUCT */
			0x7,		/* 7 */
/* 528 */	NdrFcShort( 0x20 ),	/* 32 */
/* 530 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 532 */	NdrFcShort( 0xfdf8 ),	/* Offset= -520 (12) */
/* 534 */	0xb,		/* FC_HYPER */
			0xb,		/* FC_HYPER */
/* 536 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 538 */	
			0x21,		/* FC_BOGUS_ARRAY */
			0x7,		/* 7 */
/* 540 */	NdrFcShort( 0x0 ),	/* 0 */
/* 542 */	0x19,		/* Corr desc:  field pointer, FC_ULONG */
			0x0,		/*  */
/* 544 */	NdrFcShort( 0x8 ),	/* 8 */
/* 546 */	NdrFcShort( 0x1 ),	/* Corr flags:  early, */
/* 548 */	NdrFcLong( 0xffffffff ),	/* -1 */
/* 552 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 554 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 556 */	NdrFcShort( 0xffe2 ),	/* Offset= -30 (526) */
/* 558 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 560 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x3,		/* 3 */
/* 562 */	NdrFcShort( 0x18 ),	/* 24 */
/* 564 */	NdrFcShort( 0x0 ),	/* 0 */
/* 566 */	NdrFcShort( 0x8 ),	/* Offset= 8 (574) */
/* 568 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 570 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 572 */	0x36,		/* FC_POINTER */
			0x5b,		/* FC_END */
/* 574 */	
			0x12, 0x0,	/* FC_UP */
/* 576 */	NdrFcShort( 0xffda ),	/* Offset= -38 (538) */
/* 578 */	
			0x1a,		/* FC_BOGUS_STRUCT */
			0x7,		/* 7 */
/* 580 */	NdrFcShort( 0x78 ),	/* 120 */
/* 582 */	NdrFcShort( 0x0 ),	/* 0 */
/* 584 */	NdrFcShort( 0x1e ),	/* Offset= 30 (614) */
/* 586 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 588 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 590 */	NdrFcShort( 0xfdbe ),	/* Offset= -578 (12) */
/* 592 */	0x4c,		/* FC_EMBEDDED_COMPLEX */
			0x0,		/* 0 */
/* 594 */	NdrFcShort( 0xfdba ),	/* Offset= -582 (12) */
/* 596 */	0x36,		/* FC_POINTER */
			0x8,		/* FC_LONG */
/* 598 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 600 */	0x40,		/* FC_STRUCTPAD4 */
			0x36,		/* FC_POINTER */
/* 602 */	0x8,		/* FC_LONG */
			0x8,		/* FC_LONG */
/* 604 */	0xb,		/* FC_HYPER */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 606 */	0x0,		/* 0 */
			NdrFcShort( 0xfe3d ),	/* Offset= -451 (156) */
			0x36,		/* FC_POINTER */
/* 610 */	0x8,		/* FC_LONG */
			0x40,		/* FC_STRUCTPAD4 */
/* 612 */	0x5c,		/* FC_PAD */
			0x5b,		/* FC_END */
/* 614 */	
			0x12, 0x0,	/* FC_UP */
/* 616 */	NdrFcShort( 0xfe56 ),	/* Offset= -426 (190) */
/* 618 */	
			0x12, 0x0,	/* FC_UP */
/* 620 */	NdrFcShort( 0xff8a ),	/* Offset= -118 (502) */
/* 622 */	
			0x12, 0x0,	/* FC_UP */
/* 624 */	NdrFcShort( 0xffc0 ),	/* Offset= -64 (560) */
/* 626 */	
			0x11, 0x4,	/* FC_RP [alloced_on_stack] */
/* 628 */	NdrFcShort( 0x2 ),	/* Offset= 2 (630) */
/* 630 */	0x30,		/* FC_BIND_CONTEXT */
			0xe1,		/* Ctxt flags:  via ptr, in, out, can't be null */
/* 632 */	0x0,		/* 0 */
			0x0,		/* 0 */

			0x0
        }
    };

static const unsigned short drsuapi_FormatStringOffsetTable[] =
    {
    0,
    60,
    90,
    120,
    188
    };


#ifdef __cplusplus
namespace {
#endif
static const MIDL_STUB_DESC drsuapi_StubDesc = 
    {
    (void *)& drsuapi___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &drsuapi__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    drsuapi__MIDL_TypeFormatString.Format,
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

