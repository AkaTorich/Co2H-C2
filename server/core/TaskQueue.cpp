#include "TaskQueue.hpp"

namespace co2h::server {

std::uint64_t TaskQueue::enqueue(const std::string& beacon_id,
                                 proto::TaskOp op,
                                 Bytes payload,
                                 std::int64_t operator_id) {
    std::lock_guard lk{mu_};
    Task t;
    t.id          = next_id_++;
    t.op          = op;
    t.payload     = std::move(payload);
    t.operator_id = operator_id;
    q_[beacon_id].push_back(std::move(t));
    return t.id;
}

std::vector<Task> TaskQueue::drain(const std::string& beacon_id) {
    std::lock_guard lk{mu_};
    auto it = q_.find(beacon_id);
    if (it == q_.end() || it->second.empty()) return {};
    std::vector<Task> out{std::make_move_iterator(it->second.begin()),
                          std::make_move_iterator(it->second.end())};
    it->second.clear();
    return out;
}

std::size_t TaskQueue::size_estimate() {
    std::lock_guard lk{mu_};
    std::size_t n = 0;
    for (auto& [_, d] : q_) n += d.size();
    return n;
}

}
