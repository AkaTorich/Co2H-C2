#pragma once

// Co2H Plugin SDK — публичный интерфейс плагина.
// Каждая DLL/SO должна экспортировать две C-функции:
//   co2h_plugin_create()  → возвращает IClientPlugin*
//   co2h_plugin_destroy() → освобождает экземпляр

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
    const char* name;        // короткое имя ("recon_tab")
    const char* version;     // semver ("1.0.0")
    const char* author;
    const char* description; // одна строка
};

// Интерфейс, реализуемый каждым плагином.
class IClientPlugin {
public:
    virtual ~IClientPlugin() = default;

    // Метаданные плагина.
    virtual PluginInfo info() const = 0;

    // Вызывается один раз после загрузки. ctx — доступ ко всему API клиента.
    virtual void initialize(PluginContext* ctx) = 0;

    // Вызывается перед выгрузкой. Освободить ресурсы.
    virtual void shutdown() = 0;
};

} // namespace co2h::client::plugin

// Плагин обязан определить:
//   CO2H_PLUGIN_EXPORT co2h::client::plugin::IClientPlugin* co2h_plugin_create();
//   CO2H_PLUGIN_EXPORT void co2h_plugin_destroy(co2h::client::plugin::IClientPlugin*);
