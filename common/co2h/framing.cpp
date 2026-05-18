#include "framing.hpp"

namespace co2h {

void FrameDecoder::feed(BytesView chunk) {
    if (too_large_) return;
    buf_.insert(buf_.end(), chunk.begin(), chunk.end());
    if (buf_.size() >= 4) {
        const std::uint32_t len = read_u32_be(buf_.data());
        if (len == 0 || len > max_frame_) too_large_ = true;
    }
}

std::optional<proto::Frame> FrameDecoder::next() {
    if (too_large_) return std::nullopt;
    if (buf_.size() < 4) return std::nullopt;

    const std::uint32_t len = read_u32_be(buf_.data());
    if (len == 0 || len > max_frame_) {
        too_large_ = true;
        return std::nullopt;
    }
    if (buf_.size() < 4u + len) return std::nullopt;

    proto::Frame f;
    f.type = static_cast<proto::MsgType>(buf_[4]);
    f.payload.assign(buf_.begin() + 5, buf_.begin() + 4 + len);

    buf_.erase(buf_.begin(), buf_.begin() + 4 + len);
    return f;
}

void encode_frame(Bytes& dst, proto::MsgType type, BytesView payload) {
    const std::uint32_t body = static_cast<std::uint32_t>(payload.size() + 1);
    append_u32_be(dst, body);
    dst.push_back(static_cast<std::uint8_t>(type));
    append(dst, payload);
}

}
