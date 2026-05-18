#include "SessionRegistry.hpp"

namespace co2h::server {

std::shared_ptr<BeaconSession>
SessionRegistry::create_or_update(const BeaconSession& s) {
    std::lock_guard lk{mu_};
    auto it = map_.find(s.id);
    if (it == map_.end()) {
        auto p = std::make_shared<BeaconSession>(s);
        map_.emplace(s.id, p);
        return p;
    }
    *it->second = s;
    return it->second;
}

std::shared_ptr<BeaconSession> SessionRegistry::get(const std::string& id) {
    std::lock_guard lk{mu_};
    auto it = map_.find(id);
    return it == map_.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<BeaconSession>> SessionRegistry::snapshot() {
    std::lock_guard lk{mu_};
    std::vector<std::shared_ptr<BeaconSession>> v;
    v.reserve(map_.size());
    for (auto& [_, p] : map_) v.push_back(p);
    return v;
}

}
