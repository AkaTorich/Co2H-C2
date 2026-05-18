#include "ScriptEngine.hpp"
#include "../net/ServerClient.hpp"
#include "../models/SessionsModel.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

#include <lua.hpp>

namespace co2h::client::script {

// ---- Утилита: получить ScriptEngine* из Lua state (upvalue / registry). ----
static const char* kEngineKey = "co2h_engine";

static ScriptEngine* engine_from(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, kEngineKey);
    auto* e = static_cast<ScriptEngine*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return e;
}

// ---- Конструктор / деструктор ----

ScriptEngine::ScriptEngine(QObject* parent)
    : QObject(parent) {
    L_ = luaL_newstate();
    luaL_openlibs(L_);
    // Сохраняем указатель на себя в registry.
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, kEngineKey);
}

ScriptEngine::~ScriptEngine() {
    // Освобождаем все registry refs.
    for (auto& refs : event_handlers_)
        for (int r : refs) luaL_unref(L_, LUA_REGISTRYINDEX, r);
    for (auto it = commands_.begin(); it != commands_.end(); ++it)
        luaL_unref(L_, LUA_REGISTRYINDEX, it->ref);
    if (L_) lua_close(L_);
}

void ScriptEngine::init(ServerClient* client, SessionsModel* sessions) {
    client_   = client;
    sessions_ = sessions;
    registerApi();
}

// ---- Регистрация Lua API ----

void ScriptEngine::registerApi() {
    // -- task(beacon_id, cmd_text) --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        const char* bid = luaL_checkstring(L, 1);
        const char* cmd = luaL_checkstring(L, 2);
        emit eng->taskRequested(QString::fromUtf8(bid), QString::fromUtf8(cmd));
        return 0;
    });
    lua_setglobal(L_, "task");

    // -- log(text) --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        const char* text = luaL_checkstring(L, 1);
        emit eng->logRequested(QString::fromUtf8(text));
        return 0;
    });
    lua_setglobal(L_, "log");

    // -- alert(title, text) --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        const char* title = luaL_checkstring(L, 1);
        const char* text  = luaL_checkstring(L, 2);
        emit eng->alertRequested(QString::fromUtf8(title), QString::fromUtf8(text));
        return 0;
    });
    lua_setglobal(L_, "alert");

    // -- on(event_name, callback) --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        const char* event = luaL_checkstring(L, 1);
        luaL_checktype(L, 2, LUA_TFUNCTION);
        lua_pushvalue(L, 2);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        eng->event_handlers_[QString::fromUtf8(event)].append(ref);
        return 0;
    });
    lua_setglobal(L_, "on");

    // -- command(name, help, callback) --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        const char* name = luaL_checkstring(L, 1);
        const char* help = luaL_checkstring(L, 2);
        luaL_checktype(L, 3, LUA_TFUNCTION);
        lua_pushvalue(L, 3);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);
        CmdEntry ce;
        ce.help = QString::fromUtf8(help);
        ce.ref  = ref;
        eng->commands_[QString::fromUtf8(name)] = ce;
        return 0;
    });
    lua_setglobal(L_, "command");

    // -- beacons() -> table of {id, host, user, arch, os, pid, listener} --
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = engine_from(L);
        if (!eng->sessions_) { lua_newtable(L); return 1; }
        const auto& rows = eng->sessions_->rows();
        lua_createtable(L, rows.size(), 0);
        for (int i = 0; i < rows.size(); ++i) {
            const auto& b = rows[i];
            lua_createtable(L, 0, 7);
            lua_pushstring(L, b.id.toUtf8().constData());
            lua_setfield(L, -2, "id");
            lua_pushstring(L, b.host.toUtf8().constData());
            lua_setfield(L, -2, "host");
            lua_pushstring(L, b.user.toUtf8().constData());
            lua_setfield(L, -2, "user");
            lua_pushstring(L, b.arch.toUtf8().constData());
            lua_setfield(L, -2, "arch");
            lua_pushstring(L, b.os.toUtf8().constData());
            lua_setfield(L, -2, "os");
            lua_pushinteger(L, static_cast<lua_Integer>(b.pid));
            lua_setfield(L, -2, "pid");
            lua_pushstring(L, b.listener.toUtf8().constData());
            lua_setfield(L, -2, "listener");
            lua_rawseti(L, -2, i + 1);
        }
        return 1;
    });
    lua_setglobal(L_, "beacons");
}

// ---- Загрузка скриптов ----

void ScriptEngine::loadDirectory(const QString& dir) {
    QDir d(dir);
    if (!d.exists()) return;
    const auto files = d.entryList({"*.lua"}, QDir::Files, QDir::Name);
    for (const auto& f : files)
        loadFile(d.absoluteFilePath(f));
}

bool ScriptEngine::loadFile(const QString& path) {
    if (luaL_dofile(L_, path.toUtf8().constData()) != LUA_OK) {
        const char* err = lua_tostring(L_, -1);
        emit logRequested(
            QString("[script] error loading %1: %2")
                .arg(QFileInfo(path).fileName(),
                     err ? QString::fromUtf8(err) : "unknown"));
        lua_pop(L_, 1);
        return false;
    }
    emit logRequested(
        QString("[script] loaded: %1").arg(QFileInfo(path).fileName()));
    emit scriptLoaded(path);
    return true;
}

// ---- Fire events ----

void ScriptEngine::fireBeaconNew(const QString& beaconId) {
    auto it = event_handlers_.find("beacon_new");
    if (it == event_handlers_.end()) return;
    for (int ref : *it) {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        lua_createtable(L_, 0, 1);
        lua_pushstring(L_, beaconId.toUtf8().constData());
        lua_setfield(L_, -2, "id");
        // Добавляем поля бикона если доступен.
        if (sessions_) {
            if (const auto* br = sessions_->findById(beaconId)) {
                lua_pushstring(L_, br->host.toUtf8().constData());
                lua_setfield(L_, -2, "host");
                lua_pushstring(L_, br->user.toUtf8().constData());
                lua_setfield(L_, -2, "user");
                lua_pushstring(L_, br->arch.toUtf8().constData());
                lua_setfield(L_, -2, "arch");
                lua_pushstring(L_, br->os.toUtf8().constData());
                lua_setfield(L_, -2, "os");
            }
        }
        if (lua_pcall(L_, 1, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L_, -1);
            emit logRequested(QString("[script] beacon_new error: %1")
                .arg(err ? QString::fromUtf8(err) : "?"));
            lua_pop(L_, 1);
        }
    }
}

void ScriptEngine::fireBeaconLost(const QString& beaconId) {
    auto it = event_handlers_.find("beacon_lost");
    if (it == event_handlers_.end()) return;
    for (int ref : *it) {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        lua_pushstring(L_, beaconId.toUtf8().constData());
        if (lua_pcall(L_, 1, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L_, -1);
            emit logRequested(QString("[script] beacon_lost error: %1")
                .arg(err ? QString::fromUtf8(err) : "?"));
            lua_pop(L_, 1);
        }
    }
}

void ScriptEngine::fireTaskOutput(const QString& beaconId, quint64 taskId,
                                  const QString& output) {
    auto it = event_handlers_.find("task_output");
    if (it == event_handlers_.end()) return;
    for (int ref : *it) {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        lua_pushstring(L_, beaconId.toUtf8().constData());
        lua_pushinteger(L_, static_cast<lua_Integer>(taskId));
        lua_pushstring(L_, output.toUtf8().constData());
        if (lua_pcall(L_, 3, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L_, -1);
            emit logRequested(QString("[script] task_output error: %1")
                .arg(err ? QString::fromUtf8(err) : "?"));
            lua_pop(L_, 1);
        }
    }
}

void ScriptEngine::fireChat(const QString& from, const QString& text) {
    auto it = event_handlers_.find("chat");
    if (it == event_handlers_.end()) return;
    for (int ref : *it) {
        lua_rawgeti(L_, LUA_REGISTRYINDEX, ref);
        lua_pushstring(L_, from.toUtf8().constData());
        lua_pushstring(L_, text.toUtf8().constData());
        if (lua_pcall(L_, 2, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L_, -1);
            emit logRequested(QString("[script] chat error: %1")
                .arg(err ? QString::fromUtf8(err) : "?"));
            lua_pop(L_, 1);
        }
    }
}

// ---- Пользовательские команды ----

bool ScriptEngine::hasCommand(const QString& name) const {
    return commands_.contains(name);
}

void ScriptEngine::execCommand(const QString& name, const QString& beaconId,
                               const QString& args) {
    auto it = commands_.find(name);
    if (it == commands_.end()) return;
    lua_rawgeti(L_, LUA_REGISTRYINDEX, it->ref);
    lua_pushstring(L_, beaconId.toUtf8().constData());
    lua_pushstring(L_, args.toUtf8().constData());
    if (lua_pcall(L_, 2, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L_, -1);
        emit logRequested(QString("[script] command '%1' error: %2")
            .arg(name, err ? QString::fromUtf8(err) : "?"));
        lua_pop(L_, 1);
    }
}

QVector<QPair<QString, QString>> ScriptEngine::registeredCommands() const {
    QVector<QPair<QString, QString>> out;
    out.reserve(commands_.size());
    for (auto it = commands_.begin(); it != commands_.end(); ++it)
        out.append({it.key(), it->help});
    return out;
}

}
