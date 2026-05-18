#include "ListenerManager.hpp"

#include <spdlog/spdlog.h>

namespace co2h::server {

bool ListenerManager::add(const std::string& name, Factory factory) {
    std::shared_ptr<Listener> l;
    {
        std::lock_guard lk{mu_};
        if (by_name_.count(name)) return false;
        l = factory();
        if (!l) return false;
        by_name_[name] = l;
    }
    try {
        l->start();
    } catch (const std::exception& e) {
        spdlog::error("listener '{}' failed to start: {}", name, e.what());
        std::lock_guard lk{mu_};
        by_name_.erase(name);
        return false;
    }
    return true;
}

bool ListenerManager::remove(const std::string& name) {
    std::shared_ptr<Listener> l;
    {
        std::lock_guard lk{mu_};
        auto it = by_name_.find(name);
        if (it == by_name_.end()) return false;
        l = it->second;
        by_name_.erase(it);
    }
    l->stop();
    return true;
}

std::shared_ptr<Listener> ListenerManager::get(const std::string& name) {
    std::lock_guard lk{mu_};
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<Listener>> ListenerManager::list() {
    std::lock_guard lk{mu_};
    std::vector<std::shared_ptr<Listener>> v;
    v.reserve(by_name_.size());
    for (auto& [_, p] : by_name_) v.push_back(p);
    return v;
}

void ListenerManager::stop_all() {
    std::vector<std::shared_ptr<Listener>> v;
    {
        std::lock_guard lk{mu_};
        for (auto& [_, p] : by_name_) v.push_back(p);
        by_name_.clear();
    }
    for (auto& l : v) l->stop();
}

}
