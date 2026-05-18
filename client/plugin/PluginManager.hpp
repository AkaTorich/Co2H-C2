#pragma once

#include <QObject>
#include <QString>
#include <QVector>

namespace co2h::client {
class PluginContext;
}

namespace co2h::client::plugin {
class IClientPlugin;
}

namespace co2h::client {

// Loads plugin DLLs/SOs from a directory, initializes them and
// manages their lifecycle.
class PluginManager : public QObject {
    Q_OBJECT
public:
    explicit PluginManager(PluginContext* ctx, QObject* parent = nullptr);
    ~PluginManager() override;

    // Scan directory for .dll (Windows) / .so (Linux) files, load each one.
    // Returns number of successfully loaded plugins.
    int  loadPlugins(const QString& directory);

    // Unload all plugins (calls shutdown + destroy).
    void unloadAll();

    int  count() const { return static_cast<int>(plugins_.size()); }

    struct LoadedPlugin {
        QString path;
        void*   handle   = nullptr;   // HMODULE / dlopen handle
        plugin::IClientPlugin* instance = nullptr;
    };
    const QVector<LoadedPlugin>& plugins() const { return plugins_; }

signals:
    // Emitted after each successful plugin load.
    void pluginLoaded(const QString& name, const QString& version);

private:
    PluginContext*         ctx_;
    QVector<LoadedPlugin>  plugins_;
};

} // namespace co2h::client
