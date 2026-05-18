#pragma once

// Public plugin interface for co2h client.
// Each plugin DLL/SO exports two C functions:
//   co2h_plugin_create()  → returns IClientPlugin*
//   co2h_plugin_destroy() → frees the instance

#include <cstdint>

#ifdef _WIN32
#define CO2H_PLUGIN_EXPORT extern "C" __declspec(dllexport)
#else
#define CO2H_PLUGIN_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace co2h::client {
class PluginContext;
}

namespace co2h::client::plugin {

struct PluginInfo {
    const char* name;        // short name (e.g. "recon_tab")
    const char* version;     // semver (e.g. "1.0.0")
    const char* author;
    const char* description; // one-liner
};

// Interface implemented by every plugin.
class IClientPlugin {
public:
    virtual ~IClientPlugin() = default;

    // Plugin metadata.
    virtual PluginInfo info() const = 0;

    // Called once after loading. Use ctx to register tabs, commands, handlers.
    virtual void initialize(PluginContext* ctx) = 0;

    // Called before unloading. Clean up resources.
    virtual void shutdown() = 0;
};

} // namespace co2h::client::plugin

// Plugin DLL must define:
//   CO2H_PLUGIN_EXPORT co2h::client::plugin::IClientPlugin* co2h_plugin_create();
//   CO2H_PLUGIN_EXPORT void co2h_plugin_destroy(co2h::client::plugin::IClientPlugin*);
