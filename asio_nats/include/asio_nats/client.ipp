#include "client.hpp"

#ifndef NATS_CLIENT_INLINE
#define NATS_CLIENT_INLINE
#endif

namespace nats
{
namespace error
{
namespace detail
{

class client_category: public boost::system::error_category
{
public:
    const char* name() const BOOST_SYSTEM_NOEXCEPT override
    {
        return "nats.client";
    }

    std::string message(int value) const override
    {
        switch (value) {
        case parser_error:
            return "Parser error";
        case unexpected_response:
            return "Unexpected response from server";
        case protocol_error:
            return "Unknown protocol operation";
        case connect_to_route_port:
            return "Attempted to connect to route port";
        case auth_violation:
            return "Authorization violation";
        case auth_timeout:
            return "Authorization timeout";
        case invalid_protocol:
            return "Invalid client protocol";
        case control_line_exceeded:
            return "Maximum control line exceeded";
        case server_parser_error:
            return "Server parser error";
        case not_secured:
            return "TLS required";
        case stale_connection:
            return "Stale connection";
        case connections_exceeded:
            return "Maximum connections exceeded";
        case slow_consumer:
            return "Slow consumer";
        case payload_too_big:
            return "Maximum payload violation";
        case invalid_subject:
            return "Invalid subject";
        case sub_not_allowed:
            return "Permissions violation for subscription";
        case pub_not_allowed:
            return "Permissions violation for publish";
        case batch_not_ready:
            return "Batch not redy (batch_begin required)";
        case timed_out:
            return "Timed out";
        default:
            return "?";
        }
    }
};

} // namespace detail

NATS_CLIENT_INLINE boost::system::error_category const& client_errors_category()
{
    static detail::client_category instance;
    return instance;
}

} // namespace error

namespace detail
{

NATS_CLIENT_INLINE error::client_errors parse_error_msg(string_view sv)
{
    struct error_pattern
    {
        const char *msg;
        bool full_match;
        error::client_errors code;
    };

    static std::initializer_list<error_pattern> const patterns = {
        {"UNKNOWN PROTOCOL OPERATION", true, error::protocol_error},
        {"ATTEMPTED TO CONNECT TO ROUTE PORT", true, error::connect_to_route_port},
        {"AUTHORIZATION VIOLATION", true, error::auth_violation},
        {"AUTHORIZATION TIMEOUT", true, error::auth_timeout},
        {"INVALID CLIENT PROTOCOL", true, error::invalid_protocol},
        {"MAXIMUM CONTROL LINE EXCEEDED", true, error::control_line_exceeded},
        {"PARSER ERROR", true, error::server_parser_error},
        {"SECURE CONNECTION ", false, error::not_secured},
        {"STALE CONNECTION", true, error::stale_connection},
        {"MAXIMUM CONNECTIONS EXCEEDED", true, error::connections_exceeded},
        {"SLOW CONSUMER", true, error::slow_consumer},
        {"MAXIMUM PAYLOAD VIOLATION", true, error::payload_too_big},
        {"INVALID SUBJECT", true, error::invalid_subject},
        {"INVALID PUBLISH SUBJECT", true, error::invalid_subject},
        {"PERMISSIONS VIOLATION FOR SUBSCRIPTION ", false, error::sub_not_allowed},
        {"PERMISSIONS VIOLATION FOR PUBLISH ", false, error::pub_not_allowed}
    };

    sv.remove_prefix(std::min(sv.find_first_not_of(" "), sv.size()));
    sv = sv.substr(0, std::min(sv.find_last_not_of(" "), sv.size()) + 1);
    if (sv.size() > 2 && sv.front() == '\'' && sv.back() == '\'') {
        sv.remove_prefix(1);
        sv.remove_suffix(1);
        for (auto const& p: patterns) {
            string_view msg_sv{p.msg};
            if (msg_sv.size() <= sv.size()
                && std::equal(msg_sv.begin(), msg_sv.end(), sv.begin(), [](int l, int r) {
                   return l == r || l + 32 == r;
                   })) {
                if (!p.full_match || msg_sv.size() == sv.size())
                    return p.code;
            }
        }
    }
    return error::protocol_error;
}

template<class T>
NATS_CLIENT_INLINE typename enable_if_unsigned_integer<T, bool>::type
parse_dec(const char *data, size_t size, T& v)
{
    T tmp = 0;
    for (size_t i = 0; i < size; ++i) {
        char ch = data[i];
        if (ch < '0' || ch > '9')
            return false;
        T d = ch - '0';
        if (tmp > std::numeric_limits<T>::max() / 10)
            return false;
        tmp *= 10;
        if (std::numeric_limits<T>::max() - tmp < d)
            return false;
        tmp += d;
    }
    v = tmp;
    return true;
}

NATS_CLIENT_INLINE void parser::do_move(parser& oth) noexcept
{
    if (&oth == this)
        return;

    std::copy_n(oth.args_, ARGS_MAX, args_);
    args_count_ = oth.args_count_;
    payload_size_ = oth.payload_size_;
    payload_done_ = oth.payload_done_;
    buffer_ = std::move(oth.buffer_);
    state_ = oth.state_;

    oth.state_ = parser_state::start;
    oth.args_count_ = 0;
}

NATS_CLIENT_INLINE std::pair<input_any, size_t> parser::parse(const char *data, size_t size)
{
    size_t last_i = size + 1;
    for (size_t i = 0; i < size; ++i) {
        char const c = data[i];
        switch (state_) {
        case parser_state::start:
            args_count_ = 0;
            buffer_.clear();
            switch (c) {
            case 'M':
            case 'm':
                state_ = parser_state::m;
                break;
            case 'P':
            case 'p':
                state_ = parser_state::p;
                break;
            case 'I':
            case 'i':
                state_ = parser_state::i;
                break;
            case '+':
                state_ = parser_state::plus;
                break;
            case '-':
                state_ = parser_state::minus;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::m:
            switch (c) {
            case 'S':
            case 's':
                state_ = parser_state::ms;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::ms:
            switch (c) {
            case 'G':
            case 'g':
                state_ = parser_state::msg;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::msg:
            switch (c) {
            case ' ':
            case '\t':
                state_ = parser_state::msg_spc;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::msg_spc:
            switch (c) {
            case ' ':
            case '\t':
                break;
            default:
                last_i = i;
                if (c == '\r')
                    state_ = parser_state::msg_arg_cr;
                else
                    state_ = parser_state::msg_arg;
                break;
            }
            break;

        case parser_state::msg_arg:
            if (c == '\r')
                state_ = parser_state::msg_arg_cr;
            break;

        case parser_state::msg_arg_cr:
            switch (c) {
            case '\r':
                break;
            case '\n': {
                string_view args_view;
                size_t args_offs = 0;
                if (!buffer_.empty()) {
                    buffer_.insert(buffer_.end(), data, data + i);
                    buffer_.pop_back();
                    args_view = string_view{buffer_.data(), buffer_.size()};
                } else {
                    args_view = string_view{data + last_i, i - last_i - 1};
                    args_offs = last_i;
                }
                if (parse_args(args_view) && (args_count_ > 2)
                    && parse_dec(&args_view[args_[args_count_ - 1].pos],
                            args_[args_count_ - 1].len,
                            payload_size_)) {
                    for (size_t i = 0; i < args_count_; ++i)
                        args_[i].pos += args_offs;
                    state_ = parser_state::msg_payload;
                    payload_done_ = 0;
                    last_i = i + 1;
                    break;
                }
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
                }
            default:
                state_ = parser_state::msg_arg;
                break;
            }
            break;

        case parser_state::msg_payload:
            if (payload_done_ < payload_size_) {
                auto const d = std::min(payload_size_ - payload_done_, size - i);
                payload_done_ += d;
                i += d - 1;
            } else if (c == '\r') {
                state_ = parser_state::msg_payload_cr;
            } else {
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::msg_payload_cr:
            state_ = parser_state::start;
            if (c == '\n') {
                input_data<input_type::msg> r;
                const char *args_data = data;
                if (!buffer_.empty()) {
                    buffer_.insert(buffer_.end(), data, data + i);
                    buffer_.pop_back();
                    args_data = buffer_.data();
                    r.payload = string_view{&buffer_[buffer_.size() - payload_size_], payload_size_};
                } else {
                    r.payload = string_view{data + last_i, i - last_i - 1};
                }
                r.subject = string_view{args_data + args_[0].pos, args_[0].len};
                r.sid = string_view{args_data + args_[1].pos, args_[1].len};
                if (args_count_ > 3)
                    r.reply_to = string_view{args_data + args_[2].pos, args_[2].len};
                return {r, i + 1};
            }
            return {input_data<input_type::unknown>{}, i};

        case parser_state::plus:
            switch (c) {
            case 'O':
            case 'o':
                state_ = parser_state::plus_o;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::plus_o:
            switch (c) {
            case 'K':
            case 'k':
                state_ = parser_state::plus_ok;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::plus_ok:
            if (c != '\r') {
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            state_ = parser_state::plus_ok_cr;
            break;

        case parser_state::plus_ok_cr:
            state_ = parser_state::start;
            if (c != '\n')
                return {input_data<input_type::unknown>{}, i};
            return {input_data<input_type::ok>{}, i + 1};

        case parser_state::minus:
            switch (c) {
            case 'E':
            case 'e':
                state_ = parser_state::minus_e;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::minus_e:
            switch (c) {
            case 'R':
            case 'r':
                state_ = parser_state::minus_er;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::minus_er:
            switch (c) {
            case 'R':
            case 'r':
                state_ = parser_state::minus_err;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::minus_err:
            switch (c) {
            case ' ':
            case '\t':
                state_ = parser_state::minus_err_spc;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::minus_err_spc:
            switch (c) {
            case ' ':
            case '\t':
                break;
            default:
                last_i = i;
                if (c == '\r')
                    state_ = parser_state::minus_err_arg_cr;
                else
                    state_ = parser_state::minus_err_arg;
                break;
            }
            break;

        case parser_state::minus_err_arg:
            if (c == '\r')
                state_ = parser_state::minus_err_arg_cr;
            break;

        case parser_state::minus_err_arg_cr:
            switch (c) {
            case '\r':
                break;
            case '\n': {
                state_ = parser_state::start;
                input_data<input_type::err> r;
                if (!buffer_.empty()) {
                    buffer_.insert(buffer_.end(), data, data + i);
                    buffer_.pop_back();
                    r.msg = string_view{buffer_.data(), buffer_.size()};
                } else {
                    r.msg = string_view{data + last_i, i - last_i - 1};
                }
                r.code = parse_error_msg(r.msg);
                return {r, i + 1};
                }
            default:
                state_ = parser_state::minus_err_arg;
                break;
            }
            break;

        case parser_state::p:
            switch (c) {
            case 'I':
            case 'i':
                state_ = parser_state::pi;
                break;
            case 'O':
            case 'o':
                state_ = parser_state::po;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::po:
            switch (c) {
            case 'N':
            case 'n':
                state_ = parser_state::pon;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::pon:
            switch (c) {
            case 'G':
            case 'g':
                state_ = parser_state::pong;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::pong:
            if (c != '\r') {
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            state_ = parser_state::pong_cr;
            break;

        case parser_state::pong_cr:
            state_ = parser_state::start;
            if (c != '\n')
                return {input_data<input_type::unknown>{}, i};
            return {input_data<input_type::pong>{}, i + 1};

        case parser_state::pi:
            switch (c) {
            case 'N':
            case 'n':
                state_ = parser_state::pin;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::pin:
            switch (c) {
            case 'G':
            case 'g':
                state_ = parser_state::ping;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::ping:
            if (c != '\r') {
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            state_ = parser_state::ping_cr;
            break;

        case parser_state::ping_cr:
            state_ = parser_state::start;
            if (c != '\n')
                return {input_data<input_type::unknown>{}, i};
            return {input_data<input_type::ping>{}, i + 1};

        case parser_state::i:
            switch (c) {
            case 'N':
            case 'n':
                state_ = parser_state::in;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::in:
            switch (c) {
            case 'F':
            case 'f':
                state_ = parser_state::inf;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::inf:
            switch (c) {
            case 'O':
            case 'o':
                state_ = parser_state::info;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::info:
            switch (c) {
            case ' ':
            case '\t':
                state_ = parser_state::info_spc;
                break;
            default:
                state_ = parser_state::start;
                return {input_data<input_type::unknown>{}, i};
            }
            break;

        case parser_state::info_spc:
            switch (c) {
            case ' ':
            case '\t':
                break;
            default:
                last_i = i;
                if (c == '\r')
                    state_ = parser_state::info_arg_cr;
                else
                    state_ = parser_state::info_arg;
                break;
            }
            break;

        case parser_state::info_arg:
            if (c == '\r')
                state_ = parser_state::info_arg_cr;
            break;

        case parser_state::info_arg_cr:
            switch (c) {
            case '\r':
                break;
            case '\n': {
                state_ = parser_state::start;
                input_data<input_type::info> r;
                if (!buffer_.empty()) {
                    buffer_.insert(buffer_.end(), data, data + i);
                    buffer_.pop_back();
                    r.server_info = string_view{buffer_.data(), buffer_.size()};
                } else {
                    r.server_info = string_view{data + last_i, i - last_i - 1};
                }
                return {r, i + 1};
                }
            default:
                state_ = parser_state::info_arg;
                break;
            }
            break;

        default:
            BOOST_ASSERT_MSG(false, "Unknown parser state");
        }
    }

    if (args_count_ > 0 && buffer_.empty()) {
        for (size_t i = 0; i < args_count_; ++i) {
            auto j = args_[i].pos;
            args_[i].pos = buffer_.size();
            buffer_.insert(buffer_.end(), data + j, data + j + args_[i].len);
        }
    }
    if (last_i <= size)
        buffer_.insert(buffer_.end(), data + last_i, data + size);
    else if (!buffer_.empty())
        buffer_.insert(buffer_.end(), data, data + size);

    return {input_data<input_type::need_more>{}, size};
}

NATS_CLIENT_INLINE bool parser::parse_args(string_view v) noexcept
{
    auto is_space = [] (char c) { return c == ' ' || c == '\t'; };

    auto arg_pos = std::find_if_not(v.begin(), v.end(), is_space);
    while (arg_pos != v.end()) {
        if (args_count_ == ARGS_MAX)
            return false;
        auto arg_end = std::find_if(arg_pos, v.end(), is_space);
        auto& arg = args_[args_count_++];
        arg.pos = arg_pos - v.begin();
        arg.len = arg_end - arg_pos;
        arg_pos = std::find_if_not(arg_end, v.end(), is_space);
    }
    return true;
}

} // namespace detail
} // namespace nats
