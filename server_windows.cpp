/*
 * IRFPA Management System — C++ HTTP Server (Windows / Winsock2 Edition)
 * ========================================================================
 * Converted from POSIX sockets to Winsock2 for full Windows compatibility.
 * Threading uses std::thread (C++17 stdlib) — no pthreads dependency.
 *
 * Compile with MinGW-w64 (g++):
 *   g++ -std=c++17 -O2 -o server.exe server_windows.cpp -lsqlite3 -lws2_32 -lpthread
 *
 * Compile with MSVC (Developer Command Prompt):
 *   cl /std:c++17 /O2 /EHsc server_windows.cpp sqlite3.lib Ws2_32.lib /Fe:server.exe
 *
 * Run:
 *   server.exe
 *   Open http://localhost:8080
 *
 * Prerequisites (MinGW-w64):
 *   1. Install MSYS2  →  https://www.msys2.org/
 *   2. pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-sqlite3
 *   3. Open "MSYS2 MinGW 64-bit" shell and compile with the command above.
 *
 * Prerequisites (MSVC):
 *   - Visual Studio 2019/2022 with "Desktop development with C++" workload
 *   - sqlite3.lib + sqlite3.h in your include/lib paths
 *     (download amalgamation from https://www.sqlite.org/download.html)
 *
 * Note: Winsock2 must be initialised before any socket call (WSAStartup)
 *       and cleaned up on exit (WSACleanup). Both are handled in main().
 */

// ─────────────────────────────────────────────────────────────────────────────
// Windows / Winsock2 headers  (MUST come before any other system header)
// ─────────────────────────────────────────────────────────────────────────────
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0600   // Target Windows Vista+ (required for many Winsock features)
#endif

#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used Windows headers
#include <winsock2.h>           // Core Winsock2 API  (replaces sys/socket.h + netinet/in.h)
#include <ws2tcpip.h>           // InetPton, modern address helpers  (replaces arpa/inet.h)
#include <windows.h>            // HANDLE, DWORD, general Win32 types

// ─────────────────────────────────────────────────────────────────────────────
// Standard C++ headers  (identical to Linux version)
// ─────────────────────────────────────────────────────────────────────────────
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <thread>               // std::thread — replaces pthread on both platforms
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cstdint>
#include <functional>
#include <cassert>

// ─────────────────────────────────────────────────────────────────────────────
// Windows ↔ POSIX compatibility shims
// ─────────────────────────────────────────────────────────────────────────────

// On Windows, SOCKET is an unsigned integer type (UINT_PTR), not a plain int.
// We alias it so the rest of the code can stay readable.
// INVALID_SOCKET and SOCKET_ERROR are already defined by winsock2.h.

// ssize_t does not exist on MSVC; define it for recv/send return values.
#if defined(_MSC_VER) && !defined(ssize_t)
  typedef int ssize_t;
#endif

// gmtime_r is POSIX-only; Windows provides gmtime_s (parameters reversed).
// Provide a thin inline wrapper so our timestamp code is unchanged.
inline struct tm* gmtime_r_win(const time_t* t, struct tm* result) {
#if defined(_MSC_VER)
    gmtime_s(result, t);        // MSVC: gmtime_s(struct tm*, const time_t*)
#else
    // MinGW usually has gmtime_r; if not, fall back to the non-reentrant version
    #if defined(__MINGW32__) || defined(__MINGW64__)
        struct tm* tmp = gmtime(t);
        if (tmp) *result = *tmp;
    #else
        gmtime_r(t, result);    // real POSIX
    #endif
#endif
    return result;
}
// Macro so existing call sites (gmtime_r(&t, &tm)) work without edits.
#define gmtime_r(t, r)  gmtime_r_win((t), (r))

// SO_REUSEPORT does not exist on Windows; silently drop it.
#ifndef SO_REUSEPORT
#  define SO_REUSEPORT 0
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Inline SQLite3 C API declarations
// (identical to Linux version — sqlite3 is cross-platform)
// ─────────────────────────────────────────────────────────────────────────────
extern "C" {
  struct sqlite3;
  struct sqlite3_stmt;

  #define SQLITE_OK    0
  #define SQLITE_ROW   100
  #define SQLITE_DONE  101
  #define SQLITE_TRANSIENT  ((void(*)(void*))(-1))
  #define SQLITE_STATIC     ((void(*)(void*))(0))

  int         sqlite3_open      (const char* filename, sqlite3** ppDb);
  int         sqlite3_close     (sqlite3* db);
  const char* sqlite3_errmsg    (sqlite3* db);
  int         sqlite3_exec      (sqlite3* db, const char* sql,
                                  int(*cb)(void*,int,char**,char**),
                                  void* arg, char** errmsg);
  void        sqlite3_free      (void* p);
  int         sqlite3_prepare_v2(sqlite3* db, const char* sql, int nByte,
                                  sqlite3_stmt** ppStmt, const char** pzTail);
  int         sqlite3_step      (sqlite3_stmt* pStmt);
  int         sqlite3_finalize  (sqlite3_stmt* pStmt);
  int         sqlite3_bind_text (sqlite3_stmt*, int, const char*, int n, void(*)(void*));
  int         sqlite3_bind_int  (sqlite3_stmt*, int, int);
  int         sqlite3_column_int(sqlite3_stmt*, int iCol);
  const unsigned char* sqlite3_column_text(sqlite3_stmt*, int iCol);
  long long   sqlite3_last_insert_rowid(sqlite3* db);
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
static const int    PORT                 = 8080;
static const char*  DB_PATH              = "irfpa_management.db";
static const char*  SECRET_KEY           = "irfpa-secret-key-change-in-production";
static const int    TOKEN_EXPIRE_MINUTES = 60;

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256  (public domain, RFC 6234 — fully portable, no OS dependency)
// ─────────────────────────────────────────────────────────────────────────────
namespace sha256_impl {
  static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };

  inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
  inline uint32_t Ch (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
  inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
  inline uint32_t S0 (uint32_t x) { return rotr(x,2)^rotr(x,13)^rotr(x,22); }
  inline uint32_t S1 (uint32_t x) { return rotr(x,6)^rotr(x,11)^rotr(x,25); }
  inline uint32_t s0 (uint32_t x) { return rotr(x,7)^rotr(x,18)^(x>>3); }
  inline uint32_t s1 (uint32_t x) { return rotr(x,17)^rotr(x,19)^(x>>10); }

  void compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
             ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++)
      w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t T1 = hh + S1(e) + Ch(e,f,g) + K[i] + w[i];
      uint32_t T2 = S0(a) + Maj(a,b,c);
      hh=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
  }

  std::string hash(const void* data, size_t len) {
    uint32_t h[8] = {
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    const uint8_t* msg = (const uint8_t*)data;
    uint8_t block[64];
    uint64_t bit_len = (uint64_t)len * 8;

    size_t i = 0;
    while (i + 64 <= len) { compress(h, msg + i); i += 64; }

    size_t rem = len - i;
    memcpy(block, msg + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
      while (rem < 64) block[rem++] = 0;
      compress(h, block);
      rem = 0;
    }
    while (rem < 56) block[rem++] = 0;
    for (int j = 7; j >= 0; j--) block[55 + (8-j)] = (uint8_t)(bit_len >> (j*8));
    compress(h, block);

    std::string result(32, '\0');
    for (int j = 0; j < 8; j++) {
      result[j*4+0] = (char)(h[j] >> 24);
      result[j*4+1] = (char)(h[j] >> 16);
      result[j*4+2] = (char)(h[j] >>  8);
      result[j*4+3] = (char)(h[j]      );
    }
    return result;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto helpers  (unchanged — purely algorithmic, no OS calls)
// ─────────────────────────────────────────────────────────────────────────────
std::string hex_encode(const std::string& s) {
  static const char* H = "0123456789abcdef";
  std::string r(s.size() * 2, ' ');
  for (size_t i = 0; i < s.size(); i++) {
    r[2*i]   = H[(unsigned char)s[i] >> 4];
    r[2*i+1] = H[(unsigned char)s[i] & 0xF];
  }
  return r;
}

std::string sha256_hex(const std::string& s) {
  return hex_encode(sha256_impl::hash(s.data(), s.size()));
}

std::string hmac_sha256(const std::string& key, const std::string& msg) {
  const size_t B = 64;
  std::string k = key;
  if (k.size() > B) k = sha256_impl::hash(k.data(), k.size());
  while (k.size() < B) k += '\0';

  std::string opad(B, (char)0x5c), ipad(B, (char)0x36);
  for (size_t i = 0; i < B; i++) { opad[i] ^= k[i]; ipad[i] ^= k[i]; }

  std::string inner      = ipad + msg;
  std::string inner_hash = sha256_impl::hash(inner.data(), inner.size());
  std::string outer      = opad + inner_hash;
  return sha256_impl::hash(outer.data(), outer.size());
}

std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
  return hex_encode(hmac_sha256(key, msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64URL  (no OS calls)
// ─────────────────────────────────────────────────────────────────────────────
std::string b64url_encode(const std::string& s) {
  static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string r;
  int val = 0, valb = -6;
  for (unsigned char c : s) {
    val = (val << 8) + c; valb += 8;
    while (valb >= 0) { r += T[(val >> valb) & 63]; valb -= 6; }
  }
  if (valb > -6) r += T[((val << 8) >> (valb + 8)) & 63];
  for (char& c : r) { if (c=='+') c='-'; if (c=='/') c='_'; }
  return r;
}

std::string b64url_decode(const std::string& s) {
  std::string t = s;
  for (char& c : t) { if (c=='-') c='+'; if (c=='_') c='/'; }
  while (t.size() % 4) t += '=';
  std::string r;
  int val = 0, valb = -8;
  for (unsigned char c : t) {
    int v;
    if      (c>='A'&&c<='Z') v=c-'A';
    else if (c>='a'&&c<='z') v=c-'a'+26;
    else if (c>='0'&&c<='9') v=c-'0'+52;
    else if (c=='+')         v=62;
    else if (c=='/')         v=63;
    else break;
    val=(val<<6)+v; valb+=6;
    if (valb>=0) { r+=(char)((val>>valb)&255); valb-=8; }
  }
  return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamps
// ─────────────────────────────────────────────────────────────────────────────
std::string now_string() {
  // std::chrono is cross-platform; only gmtime_r needed the shim above.
  auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  char buf[30]; struct tm tm_utc;
  gmtime_r(&t, &tm_utc);   // uses the macro shim defined at the top
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_utc);
  return buf;
}

long long now_epoch() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

// ─────────────────────────────────────────────────────────────────────────────
// String utilities  (no OS calls)
// ─────────────────────────────────────────────────────────────────────────────
std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}

std::string url_decode(const std::string& s) {
  std::string r;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i]=='%' && i+2<s.size()) {
      auto hx=[](char c){ return isdigit(c)?c-'0':toupper(c)-'A'+10; };
      r += (char)((hx(s[i+1])<<4)|hx(s[i+2])); i+=2;
    } else if (s[i]=='+') r+=' ';
    else r+=s[i];
  }
  return r;
}

std::string json_escape(const std::string& s) {
  std::string r;
  for (char c : s) {
    if      (c=='"')  r+="\\\"";
    else if (c=='\\') r+="\\\\";
    else if (c=='\n') r+="\\n";
    else if (c=='\r') r+="\\r";
    else if (c=='\t') r+="\\t";
    else              r+=c;
  }
  return r;
}

std::string json_str(const std::string& j, const std::string& key) {
  std::string needle = "\""+key+"\"";
  auto p=j.find(needle); if(p==std::string::npos) return "";
  p=j.find(':',p+needle.size()); if(p==std::string::npos) return "";
  p=j.find('"',p+1); if(p==std::string::npos) return "";
  p++;
  std::string r;
  while (p<j.size()&&j[p]!='"') {
    if (j[p]=='\\'&&p+1<j.size()) {
      p++;
      char c=j[p];
      if(c=='"')r+='"'; else if(c=='\\')r+='\\';
      else if(c=='n')r+='\n'; else if(c=='r')r+='\r';
      else if(c=='t')r+='\t'; else r+=c;
    } else r+=j[p];
    p++;
  }
  return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
std::string create_jwt(const std::string& username) {
  std::string header  = b64url_encode(R"({"alg":"HS256","typ":"JWT"})");
  std::string payload = b64url_encode(
    "{\"sub\":\""+json_escape(username)+
    "\",\"exp\":"+std::to_string(now_epoch()+TOKEN_EXPIRE_MINUTES*60)+"}");
  std::string si = header+"."+payload;
  return si+"."+b64url_encode(hmac_sha256(SECRET_KEY, si));
}

std::string verify_jwt(const std::string& token) {
  auto d1=token.find('.');          if(d1==std::string::npos) return "";
  auto d2=token.find('.',d1+1);     if(d2==std::string::npos) return "";
  std::string si  = token.substr(0,d2);
  std::string sig = token.substr(d2+1);
  if (sig != b64url_encode(hmac_sha256(SECRET_KEY,si))) return "";
  std::string pj = b64url_decode(token.substr(d1+1,d2-d1-1));
  auto ep=pj.find("\"exp\":"); if(ep==std::string::npos) return "";
  if (now_epoch() > std::stoll(pj.substr(ep+6))) return "";
  auto sp=pj.find("\"sub\":\""); if(sp==std::string::npos) return "";
  sp+=7; auto se=pj.find('"',sp); if(se==std::string::npos) return "";
  return pj.substr(sp,se-sp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Database layer  (unchanged — SQLite3 is fully cross-platform)
// ─────────────────────────────────────────────────────────────────────────────
static std::mutex db_mutex;

sqlite3* open_db() {
  sqlite3* db=nullptr;
  if (sqlite3_open(DB_PATH,&db)!=SQLITE_OK) {
    std::cerr<<"[DB] open error: "<<sqlite3_errmsg(db)<<"\n"; return nullptr;
  }
  sqlite3_exec(db,"PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;",nullptr,nullptr,nullptr);
  return db;
}

void init_db() {
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return;

  const char* ddl = R"SQL(
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL CHECK(role IN ('admin','operator')),
    assigned_stage TEXT,
    created_at     TEXT DEFAULT (datetime('now')),
    last_login     TEXT,
    is_active      INTEGER DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS stages (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS data_entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    stage_id     TEXT NOT NULL,
    element_name TEXT NOT NULL,
    value        TEXT NOT NULL,
    unit         TEXT DEFAULT '',
    device       TEXT DEFAULT '',
    notes        TEXT DEFAULT '',
    image_data   TEXT DEFAULT '',
    image_name   TEXT DEFAULT '',
    created_by   INTEGER NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    action       TEXT NOT NULL,
    table_name   TEXT NOT NULL,
    record_id    INTEGER,
    stage_id     TEXT,
    element_name TEXT,
    old_value    TEXT,
    new_value    TEXT,
    timestamp    TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_de_stage  ON data_entries(stage_id);
  CREATE INDEX IF NOT EXISTS idx_de_device ON data_entries(device);
  CREATE INDEX IF NOT EXISTS idx_de_by     ON data_entries(created_by);
  CREATE INDEX IF NOT EXISTS idx_al_user   ON audit_logs(user_id);
  CREATE INDEX IF NOT EXISTS idx_al_ts     ON audit_logs(timestamp);
  )SQL";

  char* err=nullptr;
  sqlite3_exec(db,ddl,nullptr,nullptr,&err);
  if(err){std::cerr<<"[DB] DDL: "<<err<<"\n"; sqlite3_free(err);}

  sqlite3_exec(db,R"SQL(
    INSERT OR IGNORE INTO stages (id,name,description) VALUES
      ('czt_substrate','CZT Substrate',           'CZT substrate preparation and characterization'),
      ('epilayer',     'Epilayer',                'Epitaxial layer growth and analysis'),
      ('fabrication',  'Fabrication',             'Device fabrication and processing'),
      ('measurement',  'Measurement',             'Electrical and optical measurements'),
      ('hybridization','Hybridization',           'Chip hybridization and bonding'),
      ('assembly',     'Assembly',               'Package assembly and integration'),
      ('testing',      'Testing and Demonstration','Final testing and demonstration'),
      ('archive',      'Archive',                'Data archival and documentation');
  )SQL",nullptr,nullptr,nullptr);

  auto add_user=[&](const char* u,const char* p,const char* role,const char* stage){
    std::string h=sha256_hex(p);
    std::string sql="INSERT OR IGNORE INTO users (username,password_hash,role,assigned_stage) VALUES ('"+
      std::string(u)+"','"+h+"','"+role+"',"+(stage?("'"+std::string(stage)+"'"):"NULL")+");";
    sqlite3_exec(db,sql.c_str(),nullptr,nullptr,nullptr);
  };
  add_user("admin",          "admin123","admin",    nullptr);
  add_user("substrate_op",   "pass123", "operator","czt_substrate");
  add_user("epilayer_op",    "pass123", "operator","epilayer");
  add_user("fab_op",         "pass123", "operator","fabrication");
  add_user("measurement_op", "pass123", "operator","measurement");
  add_user("hybrid_op",      "pass123", "operator","hybridization");
  add_user("assembly_op",    "pass123", "operator","assembly");
  add_user("test_op",        "pass123", "operator","testing");
  add_user("archive_op",     "pass123", "operator","archive");

  sqlite3_close(db);
  std::cout<<"[DB] Ready: "<<DB_PATH<<"\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP request / response types  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
struct Req {
  std::string method,path,query_string;
  std::map<std::string,std::string> headers;
  std::string body;

  std::map<std::string,std::string> qparams() const {
    std::map<std::string,std::string> m;
    std::istringstream ss(query_string); std::string tok;
    while(std::getline(ss,tok,'&')){
      auto eq=tok.find('=');
      if(eq!=std::string::npos) m[url_decode(tok.substr(0,eq))]=url_decode(tok.substr(eq+1));
    }
    return m;
  }

  std::string bearer() const {
    auto it=headers.find("authorization"); if(it==headers.end()) return "";
    if(it->second.size()>7&&it->second.substr(0,7)=="Bearer ") return it->second.substr(7);
    return "";
  }
};

struct Res {
  int status=200;
  std::string content_type="application/json";
  std::string body;
  std::map<std::string,std::string> extra_headers;

  static Res json(const std::string& b,int s=200){Res r;r.status=s;r.body=b;return r;}
  static Res html(const std::string& b){Res r;r.content_type="text/html; charset=utf-8";r.body=b;return r;}
  static Res err (const std::string& m,int s=400){return json("{\"error\":\""+json_escape(m)+"\"}",s);}
};

// ─────────────────────────────────────────────────────────────────────────────
// Auth helper  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
bool authenticate(const Req& req,std::map<std::string,std::string>& usr){
  std::string tok=req.bearer(); if(tok.empty()) return false;
  std::string uname=verify_jwt(tok); if(uname.empty()) return false;
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return false;
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT id,username,role,assigned_stage,last_login FROM users WHERE username=? AND is_active=1",
    -1,&s,nullptr);
  sqlite3_bind_text(s,1,uname.c_str(),-1,SQLITE_STATIC);
  bool ok=false;
  if(sqlite3_step(s)==SQLITE_ROW){
    ok=true;
    auto col=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
    usr["id"]             =std::to_string(sqlite3_column_int(s,0));
    usr["username"]       =col(1); usr["role"]=col(2);
    usr["assigned_stage"] =col(3); usr["last_login"]=col(4);
  }
  sqlite3_finalize(s); sqlite3_close(db);
  return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// API handlers  (all unchanged — pure C++ / SQLite, no OS socket calls)
// ─────────────────────────────────────────────────────────────────────────────

Res h_login(const Req& req){
  auto uname=json_str(req.body,"username"), pass=json_str(req.body,"password");
  if(uname.empty()||pass.empty()) return Res::err("Missing credentials",400);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT id,username,role,assigned_stage FROM users WHERE username=? AND password_hash=? AND is_active=1",
    -1,&s,nullptr);
  std::string h=sha256_hex(pass);
  sqlite3_bind_text(s,1,uname.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,2,h.c_str(),-1,SQLITE_STATIC);
  if(sqlite3_step(s)!=SQLITE_ROW){sqlite3_finalize(s);sqlite3_close(db);return Res::err("Invalid credentials",401);}
  int uid=sqlite3_column_int(s,0);
  auto col=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
  std::string un=col(1),role=col(2),astage=col(3);
  sqlite3_finalize(s);
  sqlite3_exec(db,("UPDATE users SET last_login=datetime('now') WHERE id="+std::to_string(uid)).c_str(),nullptr,nullptr,nullptr);
  sqlite3_exec(db,("INSERT INTO audit_logs(user_id,action,table_name) VALUES("+std::to_string(uid)+",'LOGIN','users')").c_str(),nullptr,nullptr,nullptr);
  sqlite3_close(db);
  std::string tok=create_jwt(un);
  return Res::json("{\"access_token\":\""+tok+"\",\"token_type\":\"bearer\","
                   "\"user\":{\"id\":"+std::to_string(uid)+",\"username\":\""+json_escape(un)+"\""
                   ",\"role\":\""+role+"\",\"assigned_stage\":\""+json_escape(astage)+"\"}}");
}

Res h_me(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  return Res::json("{\"id\":"+u["id"]+",\"username\":\""+json_escape(u["username"])+"\""
                   ",\"role\":\""+u["role"]+"\",\"assigned_stage\":\""+json_escape(u["assigned_stage"])+"\""
                   ",\"last_login\":\""+json_escape(u["last_login"])+"\"}");
}

Res h_stages(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,"SELECT id,name,description FROM stages ORDER BY rowid",-1,&s,nullptr);
  std::string r="["; bool first=true;
  while(sqlite3_step(s)==SQLITE_ROW){
    if(!first)r+=","; first=false;
    auto c=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
    r+="{\"id\":\""+json_escape(c(0))+"\",\"name\":\""+json_escape(c(1))+"\",\"description\":\""+json_escape(c(2))+"\"}";
  }
  r+="]"; sqlite3_finalize(s); sqlite3_close(db);
  return Res::json(r);
}

Res h_create_entry(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  auto stage_id=json_str(req.body,"stage_id"), element_name=json_str(req.body,"element_name"),
       value=json_str(req.body,"value"),       unit=json_str(req.body,"unit"),
       device=json_str(req.body,"device"),     notes=json_str(req.body,"notes"),
       image_data=json_str(req.body,"image_data"), image_name=json_str(req.body,"image_name");
  if(stage_id.empty()||element_name.empty()||value.empty()) return Res::err("Missing required fields",400);
  if(u["role"]!="admin"&&u["assigned_stage"]!=stage_id) return Res::err("Access denied to this stage",403);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "INSERT INTO data_entries(stage_id,element_name,value,unit,device,notes,image_data,image_name,created_by)"
    " VALUES(?,?,?,?,?,?,?,?,?)",
    -1,&s,nullptr);
  sqlite3_bind_text(s,1,stage_id.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,2,element_name.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,3,value.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,4,unit.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,5,device.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,6,notes.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,7,image_data.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_text(s,8,image_name.c_str(),-1,SQLITE_STATIC);
  sqlite3_bind_int(s,9,std::stoi(u["id"]));
  if(sqlite3_step(s)!=SQLITE_DONE){
    std::string e=sqlite3_errmsg(db); sqlite3_finalize(s); sqlite3_close(db);
    return Res::err("DB insert error: "+e,500);
  }
  long long eid=sqlite3_last_insert_rowid(db);
  sqlite3_finalize(s);
  sqlite3_exec(db,("INSERT INTO audit_logs(user_id,action,table_name,record_id,stage_id,element_name,new_value)"
    " VALUES("+u["id"]+",'CREATE','data_entries',"+std::to_string(eid)+",'"+stage_id+"','"+element_name+"','"+value+"')").c_str(),
    nullptr,nullptr,nullptr);
  // Auto-archive
  if(!device.empty()){
    sqlite3_stmt* cs;
    sqlite3_prepare_v2(db,
      "SELECT COUNT(DISTINCT stage_id) FROM data_entries WHERE device=?"
      " AND stage_id IN('czt_substrate','epilayer','fabrication','measurement','hybridization','assembly','testing')",
      -1,&cs,nullptr);
    sqlite3_bind_text(cs,1,device.c_str(),-1,SQLITE_STATIC);
    int completed=(sqlite3_step(cs)==SQLITE_ROW)?sqlite3_column_int(cs,0):0;
    sqlite3_finalize(cs);
    sqlite3_prepare_v2(db,"SELECT COUNT(*) FROM data_entries WHERE device=? AND stage_id='archive'",-1,&cs,nullptr);
    sqlite3_bind_text(cs,1,device.c_str(),-1,SQLITE_STATIC);
    int archived=(sqlite3_step(cs)==SQLITE_ROW)?sqlite3_column_int(cs,0):0;
    sqlite3_finalize(cs);
    if(completed>=7&&archived==0){
      sqlite3_prepare_v2(db,"SELECT id FROM users WHERE role='admin' LIMIT 1",-1,&cs,nullptr);
      int admin_id=1; if(sqlite3_step(cs)==SQLITE_ROW) admin_id=sqlite3_column_int(cs,0);
      sqlite3_finalize(cs);
      auto ai=[&](const std::string& en,const std::string& ev){
        sqlite3_prepare_v2(db,
          "INSERT INTO data_entries(stage_id,element_name,value,unit,device,notes,created_by)"
          " VALUES('archive',?,?,?,?,'Auto-archived after completing all processing stages',?)",
          -1,&cs,nullptr);
        sqlite3_bind_text(cs,1,en.c_str(),-1,SQLITE_STATIC);
        sqlite3_bind_text(cs,2,ev.c_str(),-1,SQLITE_STATIC);
        sqlite3_bind_text(cs,3,"",-1,SQLITE_STATIC);
        sqlite3_bind_text(cs,4,device.c_str(),-1,SQLITE_STATIC);
        sqlite3_bind_int(cs,5,admin_id);
        sqlite3_step(cs); sqlite3_finalize(cs);
      };
      ai("Storage_Location",     "Rack-"+device.substr(0,8));
      ai("Documentation_Status", "Complete");
      ai("Retention_Period",     "10 years");
      ai("Access_Level",         "Restricted");
    }
  }
  sqlite3_close(db);
  return Res::json("{\"id\":"+std::to_string(eid)+",\"stage_id\":\""+json_escape(stage_id)+"\""
    ",\"element_name\":\""+json_escape(element_name)+"\",\"value\":\""+json_escape(value)+"\""
    ",\"unit\":\""+json_escape(unit)+"\",\"device\":\""+json_escape(device)+"\""
    ",\"notes\":\""+json_escape(notes)+"\",\"has_image\":"+(!image_data.empty()?"true":"false")+
    ",\"image_name\":\""+json_escape(image_name)+"\",\"created_by\":\""+json_escape(u["username"])+"\""
    ",\"created_at\":\""+now_string()+"\",\"updated_at\":\""+now_string()+"\"}",201);
}

Res h_get_entries(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  auto p=req.qparams();
  std::string sf=p.count("stage_id")?p.at("stage_id"):"",
              df=p.count("device")?p.at("device"):"",
              pf=p.count("parameters")?p.at("parameters"):"";
  std::string sql=
    "SELECT de.id,de.stage_id,de.element_name,de.value,de.unit,de.device,"
    "de.notes,(de.image_data!='' AND de.image_data IS NOT NULL) as has_image,"
    "de.image_name,u.username,de.created_at,de.updated_at"
    " FROM data_entries de JOIN users u ON de.created_by=u.id WHERE 1=1";
  if(u["role"]!="admin") sql+=" AND de.stage_id='"+u["assigned_stage"]+"'";
  else if(!sf.empty())   sql+=" AND de.stage_id='"+sf+"'";
  if(!df.empty()) sql+=" AND de.device='"+df+"'";
  if(!pf.empty()){
    std::vector<std::string> pns; std::istringstream pss(pf); std::string pp;
    while(std::getline(pss,pp,',')) pns.push_back("'"+pp+"'");
    if(!pns.empty()){
      sql+=" AND de.element_name IN (";
      for(size_t i=0;i<pns.size();i++){if(i)sql+=","; sql+=pns[i];}
      sql+=")";
    }
  }
  sql+=" ORDER BY de.created_at DESC";
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,sql.c_str(),-1,&s,nullptr);
  std::string r="["; bool first=true;
  while(sqlite3_step(s)==SQLITE_ROW){
    if(!first)r+=","; first=false;
    auto c=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
    r+="{\"id\":"+c(0)+",\"stage_id\":\""+json_escape(c(1))+"\",\"element_name\":\""+json_escape(c(2))+"\""
      ",\"value\":\""+json_escape(c(3))+"\",\"unit\":\""+json_escape(c(4))+"\",\"device\":\""+json_escape(c(5))+"\""
      ",\"notes\":\""+json_escape(c(6))+"\",\"has_image\":"+(sqlite3_column_int(s,7)?"true":"false")+
      ",\"image_name\":\""+json_escape(c(8))+"\",\"created_by\":\""+json_escape(c(9))+"\""
      ",\"created_at\":\""+json_escape(c(10))+"\",\"updated_at\":\""+json_escape(c(11))+"\"}";
  }
  r+="]"; sqlite3_finalize(s); sqlite3_close(db);
  return Res::json(r);
}

Res h_get_image(const Req& req,const std::string& id_str){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,"SELECT image_data FROM data_entries WHERE id=?",-1,&s,nullptr);
  sqlite3_bind_int(s,1,std::stoi(id_str));
  Res res;
  if(sqlite3_step(s)==SQLITE_ROW){
    auto v=sqlite3_column_text(s,0); std::string img=v?(const char*)v:"";
    if(!img.empty()){res.status=200;res.content_type="text/plain";res.body=img;}
    else res=Res::err("No image",404);
  } else res=Res::err("Not found",404);
  sqlite3_finalize(s); sqlite3_close(db);
  return res;
}

Res h_audit_logs(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  if(u["role"]!="admin")   return Res::err("Admin access required",403);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT al.id,u.username,al.action,al.table_name,al.stage_id,"
    "al.element_name,al.old_value,al.new_value,al.timestamp"
    " FROM audit_logs al JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 200",
    -1,&s,nullptr);
  std::string r="["; bool first=true;
  while(sqlite3_step(s)==SQLITE_ROW){
    if(!first)r+=","; first=false;
    auto c=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
    r+="{\"id\":"+c(0)+",\"username\":\""+json_escape(c(1))+"\",\"action\":\""+json_escape(c(2))+"\""
      ",\"table_name\":\""+json_escape(c(3))+"\",\"stage_id\":\""+json_escape(c(4))+"\""
      ",\"element_name\":\""+json_escape(c(5))+"\",\"old_value\":\""+json_escape(c(6))+"\""
      ",\"new_value\":\""+json_escape(c(7))+"\",\"timestamp\":\""+json_escape(c(8))+"\"}";
  }
  r+="]"; sqlite3_finalize(s); sqlite3_close(db);
  return Res::json(r);
}

Res h_export_audit(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  if(u["role"]!="admin")   return Res::err("Admin access required",403);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT al.timestamp,u.username,al.action,al.stage_id,al.element_name,al.old_value,al.new_value"
    " FROM audit_logs al JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC",
    -1,&s,nullptr);
  std::string csv="Timestamp,Username,Action,Stage,Element,Old Value,New Value\r\n";
  while(sqlite3_step(s)==SQLITE_ROW){
    for(int i=0;i<7;i++){
      if(i) csv+=",";
      auto v=sqlite3_column_text(s,i); std::string sv=v?(const char*)v:"";
      if(sv.find_first_of(",\"\r\n")!=std::string::npos){
        std::string e; for(char c:sv){if(c=='"')e+="\"\"";else e+=c;} csv+="\""+e+"\"";
      } else csv+=sv;
    }
    csv+="\r\n";
  }
  sqlite3_finalize(s); sqlite3_close(db);
  Res res; res.status=200; res.content_type="text/csv";
  res.extra_headers["Content-Disposition"]="attachment; filename=\"irfpa_audit_log.csv\"";
  res.body=csv; return res;
}

Res h_get_users(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  if(u["role"]!="admin")   return Res::err("Admin access required",403);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT id,username,role,assigned_stage,last_login,is_active FROM users ORDER BY username",
    -1,&s,nullptr);
  std::string r="["; bool first=true;
  while(sqlite3_step(s)==SQLITE_ROW){
    if(!first)r+=","; first=false;
    auto c=[&](int i)->std::string{auto v=sqlite3_column_text(s,i);return v?(const char*)v:"";};
    r+="{\"id\":"+std::to_string(sqlite3_column_int(s,0))+
       ",\"username\":\""+json_escape(c(1))+"\",\"role\":\""+c(2)+"\""
       ",\"assigned_stage\":\""+json_escape(c(3))+"\",\"last_login\":\""+json_escape(c(4))+"\""
       ",\"is_active\":"+std::string(sqlite3_column_int(s,5)?"true":"false")+"}";
  }
  r+="]"; sqlite3_finalize(s); sqlite3_close(db);
  return Res::json(r);
}

Res h_toggle_user(const Req& req,const std::string& id_str){
  std::map<std::string,std::string> admin;
  if(!authenticate(req,admin)) return Res::err("Unauthorized",401);
  if(admin["role"]!="admin")   return Res::err("Admin access required",403);
  if(id_str==admin["id"])      return Res::err("Cannot deactivate yourself",400);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,"SELECT is_active,username FROM users WHERE id=?",-1,&s,nullptr);
  sqlite3_bind_int(s,1,std::stoi(id_str));
  if(sqlite3_step(s)!=SQLITE_ROW){sqlite3_finalize(s);sqlite3_close(db);return Res::err("User not found",404);}
  int old_active=sqlite3_column_int(s,0);
  auto v=sqlite3_column_text(s,1); std::string tuser=v?(const char*)v:"";
  sqlite3_finalize(s);
  int new_active=old_active?0:1;
  sqlite3_prepare_v2(db,"UPDATE users SET is_active=? WHERE id=?",-1,&s,nullptr);
  sqlite3_bind_int(s,1,new_active); sqlite3_bind_int(s,2,std::stoi(id_str));
  sqlite3_step(s); sqlite3_finalize(s);
  std::string action=new_active?"ACTIVATE_USER":"DEACTIVATE_USER";
  sqlite3_exec(db,("INSERT INTO audit_logs(user_id,action,table_name,element_name,old_value,new_value)"
    " VALUES("+admin["id"]+",'"+action+"','users','"+tuser+"','"
    +(old_active?"Active":"Inactive")+"','"+(new_active?"Active":"Inactive")+"')").c_str(),
    nullptr,nullptr,nullptr);
  sqlite3_close(db);
  return Res::json("{\"is_active\":"+std::string(new_active?"true":"false")+"}");
}

Res h_get_devices(const Req& req){
  std::map<std::string,std::string> u;
  if(!authenticate(req,u)) return Res::err("Unauthorized",401);
  std::lock_guard<std::mutex> g(db_mutex);
  sqlite3* db=open_db(); if(!db) return Res::err("DB error",500);
  sqlite3_stmt* s;
  sqlite3_prepare_v2(db,
    "SELECT DISTINCT device FROM data_entries WHERE device!='' ORDER BY device",
    -1,&s,nullptr);
  std::vector<std::string> devs;
  while(sqlite3_step(s)==SQLITE_ROW){auto v=sqlite3_column_text(s,0);if(v)devs.push_back((const char*)v);}
  sqlite3_finalize(s);
  std::string r="["; bool first=true;
  for(auto& dev:devs){
    if(!first)r+=","; first=false;
    sqlite3_stmt* cs;
    sqlite3_prepare_v2(db,
      "SELECT COUNT(DISTINCT stage_id) FROM data_entries WHERE device=?"
      " AND stage_id IN('czt_substrate','epilayer','fabrication','measurement','hybridization','assembly','testing')",
      -1,&cs,nullptr);
    sqlite3_bind_text(cs,1,dev.c_str(),-1,SQLITE_STATIC);
    int completed=(sqlite3_step(cs)==SQLITE_ROW)?sqlite3_column_int(cs,0):0;
    sqlite3_finalize(cs);
    sqlite3_prepare_v2(db,"SELECT COUNT(*) FROM data_entries WHERE device=? AND stage_id='archive'",-1,&cs,nullptr);
    sqlite3_bind_text(cs,1,dev.c_str(),-1,SQLITE_STATIC);
    int archived=(sqlite3_step(cs)==SQLITE_ROW)?sqlite3_column_int(cs,0):0;
    sqlite3_finalize(cs);
    r+="{\"device\":\""+json_escape(dev)+"\",\"completed_stages\":"+std::to_string(completed)+
       ",\"total_stages\":7,\"completion_pct\":"+std::to_string((int)(100.0*completed/7))+
       ",\"is_archived\":"+std::string(archived?"true":"false")+"}";
  }
  r+="]"; sqlite3_close(db);
  return Res::json(r);
}

// ─────────────────────────────────────────────────────────────────────────────
// Frontend  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
Res serve_frontend(){
  std::ifstream f("index.html");
  if(!f.good()) return Res::html("<h1>index.html not found — run server.exe from the project folder</h1>");
  std::ostringstream ss; ss<<f.rdbuf();
  return Res::html(ss.str());
}

// ─────────────────────────────────────────────────────────────────────────────
// Router  (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
Res route(const Req& req){
  const auto& m=req.method, &p=req.path;
  if(m=="OPTIONS"){Res r;r.status=204;r.body="";return r;}
  if(p=="/"||p=="/index.html")           return serve_frontend();
  if(p=="/api/auth/login"      &&m=="POST") return h_login(req);
  if(p=="/api/users/me"        &&m=="GET")  return h_me(req);
  if(p=="/api/stages"          &&m=="GET")  return h_stages(req);
  if(p=="/api/data-entries"    &&m=="GET")  return h_get_entries(req);
  if(p=="/api/data-entries"    &&m=="POST") return h_create_entry(req);
  if(p=="/api/audit-logs/export"&&m=="GET") return h_export_audit(req);
  if(p=="/api/audit-logs"      &&m=="GET")  return h_audit_logs(req);
  if(p=="/api/users"           &&m=="GET")  return h_get_users(req);
  if(p=="/api/devices"         &&m=="GET")  return h_get_devices(req);
  if(m=="POST"&&p.size()>11&&p.substr(0,11)=="/api/users/"){
    auto pos=p.find("/toggle");
    if(pos!=std::string::npos) return h_toggle_user(req,p.substr(11,pos-11));
  }
  if(m=="GET"&&p.size()>18&&p.substr(0,18)=="/api/data-entries/"){
    auto pos=p.find("/image");
    if(pos!=std::string::npos) return h_get_image(req,p.substr(18,pos-18));
  }
  return Res::err("Not Found",404);
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP parsing / building  (unchanged — pure string logic, no socket calls)
// ─────────────────────────────────────────────────────────────────────────────
bool parse_req(const std::string& raw,Req& out){
  std::istringstream ss(raw); std::string line;
  if(!std::getline(ss,line)) return false;
  std::istringstream rl(trim(line)); std::string fp;
  rl>>out.method>>fp;
  auto q=fp.find('?');
  out.path        =(q!=std::string::npos)?fp.substr(0,q):fp;
  out.query_string=(q!=std::string::npos)?fp.substr(q+1):"";
  while(std::getline(ss,line)){
    line=trim(line); if(line.empty()) break;
    auto c=line.find(':');
    if(c!=std::string::npos){
      std::string k=trim(line.substr(0,c));
      std::transform(k.begin(),k.end(),k.begin(),::tolower);
      out.headers[k]=trim(line.substr(c+1));
    }
  }
  int cl=out.headers.count("content-length")?std::stoi(out.headers["content-length"]):0;
  if(cl>0){out.body.resize(cl);ss.read(&out.body[0],cl);}
  return true;
}

std::string build_response(const Res& r){
  static const std::map<int,const char*> ST={
    {200,"OK"},{201,"Created"},{204,"No Content"},
    {400,"Bad Request"},{401,"Unauthorized"},{403,"Forbidden"},
    {404,"Not Found"},{405,"Method Not Allowed"},{500,"Internal Server Error"}
  };
  const char* st="OK"; auto it=ST.find(r.status); if(it!=ST.end()) st=it->second;
  std::string resp="HTTP/1.1 "+std::to_string(r.status)+" "+st+"\r\n";
  resp+="Content-Type: "+r.content_type+"\r\n";
  resp+="Content-Length: "+std::to_string(r.body.size())+"\r\n";
  resp+="Access-Control-Allow-Origin: *\r\n";
  resp+="Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
  resp+="Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
  for(auto&[k,v]:r.extra_headers) resp+=k+": "+v+"\r\n";
  resp+="\r\n"+r.body;
  return resp;
}

// ─────────────────────────────────────────────────────────────────────────────
// handle_client — Windows version
//
// Changes from Linux:
//   • fd type: SOCKET  instead of int
//   • recv/send signatures are identical; no change needed
//   • close(fd) → closesocket(fd)       ← KEY CHANGE
//   • ssize_t still used for recv return; shim defined above for MSVC
// ─────────────────────────────────────────────────────────────────────────────
void handle_client(SOCKET fd) {           // <-- SOCKET (not int)
  std::string raw; raw.reserve(4096);
  char buf[8192];

  // recv() signature is identical in Winsock and POSIX
  ssize_t n = recv(fd, buf, sizeof(buf), 0);
  if (n <= 0) {
    closesocket(fd);                      // <-- closesocket() not close()
    return;
  }
  raw.append(buf, n);

  // Read remaining body bytes
  auto hend = raw.find("\r\n\r\n");
  if (hend != std::string::npos) {
    int cl = 0;
    auto cp = raw.find("Content-Length:");
    if (cp==std::string::npos) cp = raw.find("content-length:");
    if (cp!=std::string::npos && cp<hend)
      cl = std::stoi(raw.substr(cp+15));
    int got = (int)raw.size() - (int)(hend+4);
    while (got < cl && cl < 32*1024*1024) {
      n = recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) break;
      raw.append(buf, n); got += (int)n;
    }
  }

  Req req; Res res;
  if (!parse_req(raw, req)) res = Res::err("Bad Request", 400);
  else                       res = route(req);

  std::string resp = build_response(res);
  // send() signature is identical in Winsock and POSIX
  send(fd, resp.c_str(), (int)resp.size(), 0);

  closesocket(fd);                        // <-- closesocket() not close()
}

// ─────────────────────────────────────────────────────────────────────────────
// main — Windows version
//
// Changes from Linux:
//   1. WSAStartup()   — initialise Winsock DLL before ANY socket call
//   2. SOCKET type    — instead of int for all socket file descriptors
//   3. INVALID_SOCKET — instead of < 0 check for socket()/accept() errors
//   4. SOCKET_ERROR   — instead of < 0 check for bind()/listen() errors
//   5. SO_REUSEPORT   — removed (not supported on Windows; macro silences it)
//   6. signal(SIGPIPE) — removed (Winsock does not deliver SIGPIPE)
//   7. socklen_t      — defined by ws2tcpip.h; identical usage
//   8. closesocket()  — instead of close() for the server socket
//   9. WSACleanup()   — release Winsock resources on exit
// ─────────────────────────────────────────────────────────────────────────────
int main() {
  // ── 1. Initialise Winsock ──────────────────────────────────────────────────
  WSADATA wsa_data;
  // Request Winsock version 2.2 (latest stable, available since Win98/NT4 SP4)
  int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (wsa_result != 0) {
    std::cerr << "[WSA] WSAStartup failed with error: " << wsa_result << "\n";
    return 1;
  }
  // Confirm we got at least version 2.2
  if (LOBYTE(wsa_data.wVersion) < 2) {
    std::cerr << "[WSA] Could not find a usable Winsock version 2.2+\n";
    WSACleanup();
    return 1;
  }

  // ── 2. Database ────────────────────────────────────────────────────────────
  init_db();

  // ── 3. Create server socket ────────────────────────────────────────────────
  // socket() returns SOCKET (UINT_PTR) on Windows, int on POSIX.
  SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (srv == INVALID_SOCKET) {            // <-- INVALID_SOCKET, not < 0
    std::cerr << "[WSA] socket() failed: " << WSAGetLastError() << "\n";
    WSACleanup();
    return 1;
  }

  // ── 4. Socket options ──────────────────────────────────────────────────────
  // SO_REUSEADDR  — supported on Windows; same semantics as Linux
  // SO_REUSEPORT  — NOT supported on Windows; macro defined to 0 above
  //                 setsockopt with level 0 and optname 0 is a no-op.
  char opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR,
             &opt, sizeof(opt));          // same call, char* cast needed on MSVC

  // ── 5. Bind ────────────────────────────────────────────────────────────────
  sockaddr_in addr{};
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port        = htons(PORT);
  if (bind(srv, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
    std::cerr << "[WSA] bind() failed on port " << PORT
              << " (error " << WSAGetLastError() << ")\n";
    closesocket(srv);
    WSACleanup();
    return 1;
  }

  // ── 6. Listen ──────────────────────────────────────────────────────────────
  if (listen(srv, SOMAXCONN) == SOCKET_ERROR) {
    std::cerr << "[WSA] listen() failed: " << WSAGetLastError() << "\n";
    closesocket(srv);
    WSACleanup();
    return 1;
  }

  // ── 7. Banner ──────────────────────────────────────────────────────────────
  std::cout << "\n"
    << "  +==========================================+\n"
    << "  |  IRFPA/DDCA Management System -- C++    |\n"
    << "  |          Windows / Winsock2 Edition      |\n"
    << "  +==========================================+\n\n"
    << "  URL  : http://localhost:" << PORT << "\n"
    << "  DB   : " << DB_PATH << "\n\n"
    << "  Default credentials:\n"
    << "    admin          / admin123  (Administrator)\n"
    << "    substrate_op   / pass123   (CZT Substrate)\n"
    << "    epilayer_op    / pass123   (Epilayer)\n"
    << "    fab_op         / pass123   (Fabrication)\n"
    << "    measurement_op / pass123   (Measurement)\n"
    << "    hybrid_op      / pass123   (Hybridization)\n"
    << "    assembly_op    / pass123   (Assembly)\n"
    << "    test_op        / pass123   (Testing & Demo)\n"
    << "    archive_op     / pass123   (Archive)\n\n"
    << "  Press Ctrl+C to stop\n\n";

  // ── 8. Accept loop ─────────────────────────────────────────────────────────
  // std::thread is used throughout — no pthreads dependency.
  // Each client is handled in a detached thread, identical to Linux version.
  while (true) {
    sockaddr_in ca{};
    int ca_len = sizeof(ca);              // Winsock accept() takes int*, not socklen_t*
    SOCKET cfd = accept(srv, (sockaddr*)&ca, &ca_len);
    if (cfd == INVALID_SOCKET) continue; // <-- INVALID_SOCKET, not < 0

    // Spawn a detached thread per connection.
    // Lambda captures cfd by value (SOCKET is a POD/UINT_PTR).
    std::thread([cfd]() { handle_client(cfd); }).detach();
  }

  // ── 9. Cleanup (reached only if loop exits — e.g. after refactoring) ───────
  closesocket(srv);                       // <-- closesocket() not close()
  WSACleanup();                           // <-- release Winsock DLL
  return 0;
}
