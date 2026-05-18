#include "PluginManager.hpp"
#include "IClientPlugin.hpp"
#include "PluginContext.hpp"

#include <QDir>
#include <QFileInfo>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

namespace co2h::client {

// Factory / destroy function signatures.
using CreateFn  = plugin::IClientPlugin* (*)();
using DestroyFn = void (*)(plugin::IClientPlugin*);

PluginManager::PluginManager(PluginContext* ctx, QObject* parent)
    : QObject(parent), ctx_(ctx)
{}

PluginManager::~PluginManager()
{
    unloadAll();
}

int PluginManager::loadPlugins(const QString& directory)
{
    QDir dir(directory);
    if (!dir.exists()) return 0;

#ifdef _WIN32
    const QStringList filters{QStringLiteral("*.dll")};
#else
    const QStringList filters{QStringLiteral("*.so")};
#endif

    int loaded = 0;
    const auto entries = dir.entryInfoList(filters, QDir::Files);

    for (const QFileInfo& fi : entries) {
        const QString path = fi.absoluteFilePath();

#ifdef _WIN32
        HMODULE hLib = LoadLibraryW(
            reinterpret_cast<const wchar_t*>(path.utf16()));
        if (!hLib) continue;

        auto fnCreate  = reinterpret_cast<CreateFn>(
            GetProcAddress(hLib, "co2h_plugin_create"));
        auto fnDestroy = reinterpret_cast<DestroyFn>(
            GetProcAddress(hLib, "co2h_plugin_destroy"));

        if (!fnCreate || !fnDestroy) {
            FreeLibrary(hLib);
            continue;
        }
        void* handle = static_cast<void*>(hLib);
#else
        void* handle = dlopen(path.toUtf8().constData(), RTLD_NOW);
        if (!handle) continue;

        auto fnCreate  = reinterpret_cast<CreateFn>(dlsym(handle, "co2h_plugin_create"));
        auto fnDestroy = reinterpret_cast<DestroyFn>(dlsym(handle, "co2h_plugin_destroy"));

        if (!fnCreate || !fnDestroy) {
            dlclose(handle);
            continue;
        }
#endif

        plugin::IClientPlugin* inst = fnCreate();
        if (!inst) {
#ifdef _WIN32
            FreeLibrary(hLib);
#else
            dlclose(handle);
#endif
            continue;
        }

        // Initialize the plugin.
        inst->initialize(ctx_);

        LoadedPlugin lp;
        lp.path     = path;
        lp.handle   = handle;
        lp.instance = inst;
        plugins_.append(lp);

        auto pi = inst->info();
        emit pluginLoaded(QString::fromUtf8(pi.name),
                          QString::fromUtf8(pi.version));
        ++loaded;
    }

    return loaded;
}

void PluginManager::unloadAll()
{
    for (auto& lp : plugins_) {
        if (lp.instance) {
            lp.instance->shutdown();

            // Resolve destroy function again to free the instance.
#ifdef _WIN32
            auto fn = reinterpret_cast<DestroyFn>(
                GetProcAddress(static_cast<HMODULE>(lp.handle),
                               "co2h_plugin_destroy"));
#else
            auto fn = reinterpret_cast<DestroyFn>(
                dlsym(lp.handle, "co2h_plugin_destroy"));
#endif
            if (fn) fn(lp.instance);
            lp.instance = nullptr;
        }
        if (lp.handle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(lp.handle));
#else
            dlclose(lp.handle);
#endif
            lp.handle = nullptr;
        }
    }
    plugins_.clear();
}

} // namespace co2h::client
