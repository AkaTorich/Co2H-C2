#include "Database.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <chrono>

namespace co2h::server {

namespace {

std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

struct Stmt {
    explicit Stmt(sqlite3* db, const char* sql) {
        sqlite3_prepare_v2(db, sql, -1, &st, nullptr);
    }
    ~Stmt() { if (st) sqlite3_finalize(st); }
    sqlite3_stmt* st = nullptr;
};

}

Database::Database(const std::filesystem::path& path) {
    if (sqlite3_open(path.string().c_str(), &db_) != SQLITE_OK) {
        spdlog::error("sqlite3_open failed: {}", sqlite3_errmsg(db_));
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;",  nullptr, nullptr, nullptr);
}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

bool Database::exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        spdlog::error("sqlite exec failed: {}", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool Database::migrate() {
    std::lock_guard lk{mu_};
    const char* ddl =
        "CREATE TABLE IF NOT EXISTS operators ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username      TEXT NOT NULL UNIQUE,"
        "  password_hash TEXT NOT NULL,"
        "  role          TEXT NOT NULL DEFAULT 'operator',"
        "  created_at    INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  beacon_id     TEXT PRIMARY KEY,"
        "  listener      TEXT,"
        "  hostname      TEXT,"
        "  username      TEXT,"
        "  pid           INTEGER,"
        "  arch          TEXT,"
        "  internal_ip   TEXT,"
        "  external_ip   TEXT,"
        "  first_seen    INTEGER,"
        "  last_seen     INTEGER,"
        "  metadata      BLOB,"
        "  session_key   BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS tasks ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  beacon_id     TEXT NOT NULL,"
        "  op            INTEGER NOT NULL,"
        "  payload       BLOB,"
        "  status        TEXT NOT NULL DEFAULT 'queued',"
        "  created_at    INTEGER NOT NULL,"
        "  completed_at  INTEGER,"
        "  result        BLOB,"
        "  operator_id   INTEGER"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_tasks_beacon ON tasks(beacon_id,status);"
        "CREATE TABLE IF NOT EXISTS audit ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ts            INTEGER NOT NULL,"
        "  operator      TEXT NOT NULL,"
        "  action        TEXT NOT NULL,"
        "  detail        TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS listener_keys ("
        "  name          TEXT PRIMARY KEY,"
        "  key_hex       TEXT NOT NULL,"
        "  rsa_pub       BLOB,"
        "  rsa_priv      BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS credentials ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user        TEXT NOT NULL,"
        "  domain      TEXT NOT NULL DEFAULT '',"
        "  kind        TEXT NOT NULL,"
        "  secret      TEXT NOT NULL DEFAULT '',"
        "  host        TEXT NOT NULL DEFAULT '',"
        "  source      TEXT NOT NULL DEFAULT '',"
        "  note        TEXT NOT NULL DEFAULT '',"
        "  added_by    TEXT NOT NULL DEFAULT '',"
        "  added_at    INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS ix_creds_user ON credentials(user,domain);"
        "CREATE TABLE IF NOT EXISTS listeners_cfg ("
        "  name          TEXT PRIMARY KEY,"
        "  kind          TEXT NOT NULL,"
        "  bind_host     TEXT,"
        "  bind_port     INTEGER,"
        "  cert_file     TEXT,"
        "  key_file      TEXT,"
        "  profile_file  TEXT,"
        "  enabled       INTEGER DEFAULT 1"
        ");";
    if (!exec(ddl)) return false;
    // Best-effort migration for older DBs created before RSA columns existed.
    sqlite3_exec(db_, "ALTER TABLE listener_keys ADD COLUMN rsa_pub  BLOB;",
                 nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "ALTER TABLE listener_keys ADD COLUMN rsa_priv BLOB;",
                 nullptr, nullptr, nullptr);
    return true;
}

std::optional<OperatorRow> Database::find_operator(const std::string& username) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "SELECT id,username,password_hash,role,created_at "
                "FROM operators WHERE username=?1"};
    if (!s.st) return std::nullopt;
    sqlite3_bind_text(s.st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s.st) != SQLITE_ROW) return std::nullopt;

    OperatorRow r;
    r.id            = sqlite3_column_int64(s.st, 0);
    r.username      = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 1));
    r.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 2));
    r.role          = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 3));
    r.created_at    = sqlite3_column_int64(s.st, 4);
    return r;
}

std::int64_t Database::add_operator(const std::string& username,
                                    const std::string& password_hash,
                                    const std::string& role) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "INSERT INTO operators(username,password_hash,role,created_at) "
                "VALUES(?1,?2,?3,?4)"};
    if (!s.st) return 0;
    sqlite3_bind_text(s.st, 1, username.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st, 2, password_hash.c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st, 3, role.c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s.st, 4, unix_now());
    if (sqlite3_step(s.st) != SQLITE_DONE) return 0;
    return sqlite3_last_insert_rowid(db_);
}

std::vector<OperatorRow> Database::list_operators() {
    std::lock_guard lk{mu_};
    std::vector<OperatorRow> out;
    Stmt s{db_, "SELECT id,username,password_hash,role,created_at "
                "FROM operators ORDER BY id"};
    if (!s.st) return out;
    while (sqlite3_step(s.st) == SQLITE_ROW) {
        OperatorRow r;
        r.id            = sqlite3_column_int64(s.st, 0);
        r.username      = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 1));
        r.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 2));
        r.role          = reinterpret_cast<const char*>(sqlite3_column_text(s.st, 3));
        r.created_at    = sqlite3_column_int64(s.st, 4);
        out.push_back(std::move(r));
    }
    return out;
}

bool Database::delete_operator(std::int64_t id) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "DELETE FROM operators WHERE id=?1"};
    if (!s.st) return false;
    sqlite3_bind_int64(s.st, 1, id);
    if (sqlite3_step(s.st) != SQLITE_DONE) return false;
    return sqlite3_changes(db_) > 0;
}

bool Database::set_operator_password(std::int64_t id,
                                     const std::string& password_hash) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "UPDATE operators SET password_hash=?1 WHERE id=?2"};
    if (!s.st) return false;
    sqlite3_bind_text(s.st, 1, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s.st, 2, id);
    if (sqlite3_step(s.st) != SQLITE_DONE) return false;
    return sqlite3_changes(db_) > 0;
}

std::optional<std::string> Database::get_listener_key_hex(const std::string& name) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "SELECT key_hex FROM listener_keys WHERE name=?1"};
    if (!s.st) return std::nullopt;
    sqlite3_bind_text(s.st, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s.st) != SQLITE_ROW) return std::nullopt;
    return reinterpret_cast<const char*>(sqlite3_column_text(s.st, 0));
}

void Database::set_listener_key_hex(const std::string& name, const std::string& hex) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "INSERT INTO listener_keys(name,key_hex) VALUES(?1,?2) "
                "ON CONFLICT(name) DO UPDATE SET key_hex=excluded.key_hex"};
    if (!s.st) return;
    sqlite3_bind_text(s.st, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st, 2, hex.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_step(s.st);
}

bool Database::get_listener_rsa(const std::string& name,
                                Bytes& pub_blob, Bytes& priv_blob) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "SELECT rsa_pub, rsa_priv FROM listener_keys WHERE name=?1"};
    if (!s.st) return false;
    sqlite3_bind_text(s.st, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s.st) != SQLITE_ROW) return false;
    if (sqlite3_column_type(s.st, 0) == SQLITE_NULL) return false;
    if (sqlite3_column_type(s.st, 1) == SQLITE_NULL) return false;
    int pn = sqlite3_column_bytes(s.st, 0);
    int sn = sqlite3_column_bytes(s.st, 1);
    if (pn <= 0 || sn <= 0) return false;
    pub_blob.assign(static_cast<const std::uint8_t*>(sqlite3_column_blob(s.st, 0)),
                    static_cast<const std::uint8_t*>(sqlite3_column_blob(s.st, 0)) + pn);
    priv_blob.assign(static_cast<const std::uint8_t*>(sqlite3_column_blob(s.st, 1)),
                     static_cast<const std::uint8_t*>(sqlite3_column_blob(s.st, 1)) + sn);
    return true;
}

void Database::set_listener_rsa(const std::string& name,
                                BytesView pub_blob, BytesView priv_blob) {
    std::lock_guard lk{mu_};
    // listener_keys row already exists at this point — we only update RSA cols.
    Stmt s{db_, "UPDATE listener_keys SET rsa_pub=?1, rsa_priv=?2 WHERE name=?3"};
    if (!s.st) return;
    sqlite3_bind_blob(s.st, 1, pub_blob.data(),  static_cast<int>(pub_blob.size()),  SQLITE_TRANSIENT);
    sqlite3_bind_blob(s.st, 2, priv_blob.data(), static_cast<int>(priv_blob.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st, 3, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s.st);
}

std::vector<CredentialRow> Database::creds_list() {
    std::lock_guard lk{mu_};
    std::vector<CredentialRow> out;
    Stmt s{db_, "SELECT id,user,domain,kind,secret,host,source,note,added_by,added_at "
                "FROM credentials ORDER BY id DESC"};
    if (!s.st) return out;
    while (sqlite3_step(s.st) == SQLITE_ROW) {
        CredentialRow r;
        r.id        = sqlite3_column_int64(s.st, 0);
        auto col_text = [&](int c) -> std::string {
            const auto* p = sqlite3_column_text(s.st, c);
            return p ? std::string{reinterpret_cast<const char*>(p)} : std::string{};
        };
        r.user      = col_text(1);
        r.domain    = col_text(2);
        r.kind      = col_text(3);
        r.secret    = col_text(4);
        r.host      = col_text(5);
        r.source    = col_text(6);
        r.note      = col_text(7);
        r.added_by  = col_text(8);
        r.added_at  = sqlite3_column_int64(s.st, 9);
        out.push_back(std::move(r));
    }
    return out;
}

std::int64_t Database::creds_add(const CredentialRow& r) {
    std::lock_guard lk{mu_};
    // Дедупликация: если такая запись уже есть — возвращаем существующий id.
    {
        Stmt q{db_, "SELECT id FROM credentials "
                    "WHERE user=?1 AND domain=?2 AND kind=?3 AND secret=?4 LIMIT 1"};
        if (q.st) {
            sqlite3_bind_text(q.st, 1, r.user.c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q.st, 2, r.domain.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q.st, 3, r.kind.c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q.st, 4, r.secret.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(q.st) == SQLITE_ROW) {
                return sqlite3_column_int64(q.st, 0);
            }
        }
    }
    Stmt s{db_, "INSERT INTO credentials"
                "(user,domain,kind,secret,host,source,note,added_by,added_at)"
                " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)"};
    if (!s.st) return 0;
    sqlite3_bind_text (s.st, 1, r.user.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 2, r.domain.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 3, r.kind.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 4, r.secret.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 5, r.host.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 6, r.source.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 7, r.note.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (s.st, 8, r.added_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s.st, 9, r.added_at ? r.added_at : unix_now());
    if (sqlite3_step(s.st) != SQLITE_DONE) return 0;
    return sqlite3_last_insert_rowid(db_);
}

bool Database::creds_del(std::int64_t id) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "DELETE FROM credentials WHERE id=?1"};
    if (!s.st) return false;
    sqlite3_bind_int64(s.st, 1, id);
    if (sqlite3_step(s.st) != SQLITE_DONE) return false;
    return sqlite3_changes(db_) > 0;
}

void Database::log_audit(const std::string& op_username,
                         const std::string& action,
                         const std::string& detail) {
    std::lock_guard lk{mu_};
    Stmt s{db_, "INSERT INTO audit(ts,operator,action,detail) VALUES(?1,?2,?3,?4)"};
    if (!s.st) return;
    sqlite3_bind_int64(s.st, 1, unix_now());
    sqlite3_bind_text(s.st,  2, op_username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st,  3, action.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.st,  4, detail.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_step(s.st);
}

}
