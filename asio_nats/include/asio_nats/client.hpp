#ifndef NATS_CLIENT_HPP
#define NATS_CLIENT_HPP

#include <boost/asio/io_service.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/utility/string_ref.hpp>
#include <boost/optional/optional.hpp>
#include <vector>
#include <array>

namespace nats
{
namespace error
{

enum client_errors
{
    // connection closes on following errors
    parser_error = 1,
    unexpected_response,
    protocol_error,
    connect_to_route_port,
    auth_violation,
    auth_timeout,
    invalid_protocol,
    control_line_exceeded,
    server_parser_error,
    not_secured,
    stale_connection,
    connections_exceeded,
    slow_consumer,
    payload_too_big,
    // connection stays open on following errors
    invalid_subject,
    sub_not_allowed,
    pub_not_allowed,
    batch_not_ready,
    timed_out
};

boost::system::error_category const& client_errors_category();

inline boost::system::error_code make_error_code(client_errors e)
{
    return boost::system::error_code{static_cast<int>(e), client_errors_category()};
}

} // namespace error
} // namespace nats

namespace boost
{
namespace system
{

template<> struct is_error_code_enum<nats::error::client_errors>
{
    static const bool value = true;
};

} // namespace system
} // namespace boost

namespace nats
{

using string_view = boost::string_ref;

namespace detail
{

enum class parser_state
{
    start,
    plus,
    plus_o,
    plus_ok,
    plus_ok_cr,
    minus,
    minus_e,
    minus_er,
    minus_err,
    minus_err_spc,
    minus_err_arg,
    minus_err_arg_cr,
    m,
    ms,
    msg,
    msg_spc,
    msg_arg,
    msg_arg_cr,
    msg_payload,
    msg_payload_cr,
    p,
    pi,
    pin,
    ping,
    ping_cr,
    po,
    pon,
    pong,
    pong_cr,
    i,
    in,
    inf,
    info,
    info_spc,
    info_arg,
    info_arg_cr
};

enum class input_type
{
    unknown,
    need_more,
    info,
    msg,
    ping,
    pong,
    ok,
    err
};

template<input_type T>
struct input_data{};

template<>
struct input_data<input_type::info>
{
    string_view server_info;
};

template<>
struct input_data<input_type::msg>
{
    string_view subject;
    string_view sid;
    string_view reply_to;
    string_view payload;
};

template<>
struct input_data<input_type::err>
{
    string_view msg;
    error::client_errors code;
};

class input_any
{
public:
    template<input_type T>
    input_any(input_data<T> md)
    {
        type_ = T;
        static_assert(sizeof(md) <= sizeof(data_), "Not enough storage size");
        reinterpret_cast<input_data<T>*>(&data_)[0] = md;
    }

    template<input_type T>
    input_data<T> data() const
    {
        BOOST_ASSERT(type_ == T);
        return reinterpret_cast<const input_data<T>*>(&data_)[0];
    }

    input_type type() const noexcept { return type_; }

private:
    input_type type_;
    std::aligned_storage<
        sizeof(input_data<input_type::msg>) // the largest struct
            >::type data_;
};

class parser
{
public:
    parser() = default;
    parser(parser const&) = default;
    parser& operator = (parser const&) = default;

    parser(parser&& oth) noexcept
    {
        do_move(oth);
    }

    parser& operator = (parser&& oth) noexcept
    {
        do_move(oth);
        return *this;
    }

    std::pair<input_any, size_t> parse(const char *data, size_t size);

private:
    void do_move(parser& oth) noexcept;
    bool parse_args(string_view v) noexcept;

    static constexpr size_t ARGS_MAX = 4;
    struct { size_t pos; size_t len; } args_[ARGS_MAX];
    size_t args_count_ = 0;
    size_t payload_size_ = 0;
    size_t payload_done_ = 0;
    std::vector<char> buffer_;
    parser_state state_ = parser_state::start;
};

boost::asio::const_buffer to_const_buffer(string_view sv)
{
    return boost::asio::const_buffer(sv.data(), sv.size());
}

constexpr size_t max_chars(size_t x, unsigned char base = 10)
{
    return x < base ? 1 : 1 + max_chars(x / base, base);
}

template<class T, class U>
struct enable_if_unsigned_integer: std::enable_if<
    std::numeric_limits<T>::is_integer
    && !std::numeric_limits<T>::is_signed, U> {};

template<class T>
constexpr typename enable_if_unsigned_integer<T, size_t>::type
max_chars(unsigned char base = 10)
{
    return max_chars(std::numeric_limits<T>::max(), base);
}

template<class T>
typename enable_if_unsigned_integer<T, size_t>::type
write_dec(char *buf, T v)
{
    char *ptr = buf;
    do {
        *ptr++ = (v % 10) + '0';
        v /= 10;
    } while (v > 0);
    std::reverse(buf, ptr);
    return ptr - buf;
}

template<class Cancellable>
void cancel_and_forward_error(Cancellable& obj, boost::system::error_code& ec)
{
    boost::system::error_code next_ec;
    obj.cancel(next_ec);
    if (!ec && next_ec)
        ec = next_ec;
}

} // namespace detail

class authorization
{
public:
    authorization() = default;

    authorization(string_view token)
        : token_{token.to_string()}
    {}

    authorization(string_view user, string_view password)
        : user_{user.to_string()}
        , password_{password.to_string()}
    {}

    std::string const& token() const noexcept { return token_; }
    std::string const& user() const noexcept { return user_; }
    std::string const& password() const noexcept { return password_; }

private:
    std::string token_;
    std::string user_;
    std::string password_;
};

template<class HeaderContainer, class BodyContainer>
struct basic_message;

namespace detail
{

template<class SequenceContainerTo,
         class SequenceContainerFrom>
struct converter
{
    SequenceContainerTo operator ()(SequenceContainerFrom const& from) const
    {
        return SequenceContainerTo{std::begin(from), std::end(from)};
    }
};

template<class SequenceContainerTo,
         class SequenceContainerFrom>
SequenceContainerTo convert(SequenceContainerFrom const& from)
{
    converter<SequenceContainerTo, SequenceContainerFrom> cnv;
    return cnv(from);
}

template<class CharT, class Traits>
struct converter<boost::basic_string_ref<CharT, Traits>, string_view>
{
    boost::basic_string_ref<CharT, Traits> operator ()(string_view from) const
    {
        return boost::basic_string_ref<CharT, Traits>{from.data(), from.size()};
    }
};

template<class SequenceContainer>
struct header
{
    SequenceContainer subject;
    SequenceContainer sid;
    SequenceContainer reply_to;
};

template<>
struct header<void>
{};

void assign_header(header<void>&, input_data<input_type::msg> const&)
{}

template<class SequenceContainer>
void assign_header(header<SequenceContainer>& header, input_data<input_type::msg> const& data)
{
    header.subject = convert<SequenceContainer>(data.subject);
    header.sid = convert<SequenceContainer>(data.sid);
    header.reply_to = convert<SequenceContainer>(data.reply_to);
}

template<class SequenceContainer>
struct body
{
    SequenceContainer payload;
};

template<>
struct body<void>
{};

void assign_body(body<void>&, input_data<input_type::msg> const&)
{}

template<class SequenceContainer>
void assign_body(body<SequenceContainer>& body, input_data<input_type::msg> const& data)
{
    body.payload = convert<SequenceContainer>(data.payload);
}

template<class HeaderContainer, class BodyContainer>
void assign_message(basic_message<HeaderContainer, BodyContainer>& msg, input_data<input_type::msg> const& data)
{
    assign_header(msg, data);
    assign_body(msg, data);
}

} // namespace detail

template<class HeaderContainer, class BodyContainer>
struct basic_message
    : detail::header<HeaderContainer>
    , detail::body<BodyContainer>
{};

template<class BodyContainer>
using message_body = basic_message<void, BodyContainer>;

using message_void = basic_message<void, void>;
using message_view = basic_message<string_view, string_view>;
using message = basic_message<std::string, std::string>;

template<class Impl>
class basic_client;

template<template<class> class Impl, class Protocol>
class basic_client<Impl<Protocol>>
{
    using impl_type = Impl<Protocol>;
    using this_type = basic_client<impl_type>;

    enum class state
    {
        disconnected,
        wait_info,
        wait_info_ack,
        ready
    };

public:
    using endpoint_type = typename Protocol::endpoint;

    basic_client(boost::asio::io_service& io)
        : timer_{io}
    {
        buffer_.resize(4 * 1024);
        verbose_ = false;
        timer_wait_ = false;
    }

    basic_client(this_type const&) = delete;
    this_type& operator = (this_type const&) = delete;

    basic_client(this_type&&) = delete;
    this_type& operator = (this_type&&) = delete;

    bool verbose() const noexcept { return verbose_; }
    void verbose(bool v) noexcept { verbose_ = v; }

    bool connected() const noexcept
    {
        return impl().socket().is_open() && state_ == state::ready;
    }

    void connect(endpoint_type const& ep)
    {
        return connect(ep, authorization{});
    }

    void connect(endpoint_type const& ep, boost::system::error_code& ec)
    {
        return connect(ep, authorization{}, ec);
    }

    void connect(endpoint_type const& ep, authorization auth)
    {
        boost::system::error_code ec;
        connect(ep, std::move(auth), ec);
        boost::asio::detail::throw_error(ec, "connect");
    }

    void connect(endpoint_type const& ep, authorization auth, boost::system::error_code& ec)
    {
        ec.assign(0, ec.category());
        impl().socket().connect(ep, ec);
        if (ec) return;
        state_ = state::wait_info;
        message_void msg;
        read_input(impl().socket(), msg, ec);
        if (ec) return;
        do_handshake(auth, ec);
        if (ec) return;
        if (!verbose_) {
            state_ = state::ready;
        } else {
            state_ = state::wait_info_ack;
            read_input(impl().stream(), msg, ec);
        }
    }

    template<class HeaderContainer, class BodyContainer>
    void read(basic_message<HeaderContainer, BodyContainer>& msg)
    {
        boost::system::error_code ec;
        read(msg, ec);
        boost::asio::detail::throw_error(ec, "read");
    }

    template<class HeaderContainer, class BodyContainer>
    void read(basic_message<HeaderContainer, BodyContainer>& msg, boost::system::error_code& ec)
    {
        using namespace detail;
        ec.assign(0, ec.category());
        assign_message(msg, input_data<input_type::msg>());
        read_input(impl().stream(), msg, ec);
    }

    template<class HeaderContainer, class BodyContainer>
    void read_for(basic_message<HeaderContainer, BodyContainer>& msg, boost::posix_time::time_duration dur)
    {
        boost::system::error_code ec;
        read_for(msg, dur, ec);
        boost::asio::detail::throw_error(ec, "read_for");
    }

    template<class HeaderContainer, class BodyContainer>
    void read_for(basic_message<HeaderContainer, BodyContainer>& msg,  boost::posix_time::time_duration dur,
                  boost::system::error_code& ec)
    {
        using namespace detail;
        ec.assign(0, ec.category());
        assign_message(msg, input_data<input_type::msg>());
        read_input(impl().stream(), msg, ec, dur);
    }

    void close()
    {
        boost::system::error_code ec;
        close(ec);
        boost::asio::detail::throw_error(ec, "close");
    }

    void close(boost::system::error_code& ec)
    {
        data_offs_ = data_size_;
        pong_count_ = 0;
        state_ = state::disconnected;
        ec.assign(0, ec.category());
        impl().close(ec);
    }

    void batch_begin()
    {
        batch_buffer_ = std::vector<char>{};
    }

    void batch_write()
    {
        boost::system::error_code ec;
        batch_write(ec);
        boost::asio::detail::throw_error(ec, "batch_write");
    }

    void batch_write(boost::system::error_code& ec)
    {
        if (batch_buffer_) {
            ec.assign(0, ec.category());
            std::vector<char> b = std::move(*batch_buffer_);
            batch_buffer_ = boost::none;
            boost::asio::write(impl().stream(), boost::asio::buffer(b), ec);
        } else {
            ec = error::batch_not_ready;
        }
    }

    void pub(string_view subject, string_view payload)
    {
        return pub(subject, detail::to_const_buffer(payload));
    }

    void pub(string_view subject, boost::asio::const_buffer payload)
    {
        return pub(subject, {"", 0}, payload);
    }

    void pub(string_view subject, string_view payload,
             boost::system::error_code& ec)
    {
        return pub(subject, detail::to_const_buffer(payload), ec);
    }

    void pub(string_view subject, boost::asio::const_buffer payload,
             boost::system::error_code& ec)
    {
        return pub(subject, {"", 0}, payload, ec);
    }

    void pub(string_view subject, string_view reply_to, string_view payload)
    {
        return pub(subject, reply_to, detail::to_const_buffer(payload));
    }

    void pub(string_view subject, string_view reply_to, boost::asio::const_buffer payload)
    {
        boost::system::error_code ec;
        pub(subject, reply_to, payload, ec);
        boost::asio::detail::throw_error(ec, "pub");
    }

    void pub(string_view subject, string_view reply_to, string_view payload,
             boost::system::error_code& ec)
    {
        return pub(subject, reply_to, detail::to_const_buffer(payload), ec);
    }

    void pub(string_view subject, string_view reply_to, boost::asio::const_buffer payload,
             boost::system::error_code& ec)
    {
        ec.assign(0, ec.category());
        char num_data[detail::max_chars<size_t>()];
        auto num_size = detail::write_dec(num_data, boost::asio::buffer_size(payload));
        std::array<boost::asio::const_buffer, 9> buffers {{
            {"PUB ", 4},
            {subject.data(), subject.size()}, {" ", 1},
            {reply_to.data(), reply_to.size()}, {" ", 1},
            {num_data, num_size}, {"\r\n", 2},
            payload, {"\r\n", 2}
        }};
        do_write(buffers, ec);
    }

    void sub(string_view subject, string_view sid)
    {
        return sub(subject, sid, {"", 0});
    }

    void sub(string_view subject, string_view sid,
             boost::system::error_code& ec)
    {
        return sub(subject, sid, {"", 0}, ec);
    }

    void sub(string_view subject, string_view sid, string_view queue_group)
    {
        boost::system::error_code ec;
        sub(subject, sid, queue_group, ec);
        boost::asio::detail::throw_error(ec, "sub");
    }

    void sub(string_view subject, string_view sid, string_view queue_group,
             boost::system::error_code& ec)
    {
        ec.assign(0, ec.category());
        std::array<boost::asio::const_buffer, 7> buffers {{
            {"SUB ", 4},
            {subject.data(), subject.size()}, {" ", 1},
            {queue_group.data(), queue_group.size()}, {" ", 1},
            {sid.data(), sid.size()}, {"\r\n", 2}
        }};
        do_write(buffers, ec);
    }

    void unsub(string_view sid)
    {
        boost::system::error_code ec;
        unsub(sid, ec);
        boost::asio::detail::throw_error(ec, "unsub");
    }

    void unsub(string_view sid, boost::system::error_code& ec)
    {
        ec.assign(0, ec.category());
        std::array<boost::asio::const_buffer, 3> buffers {{
            {"UNSUB ", 6},
            {sid.data(), sid.size()}, {"\r\n", 2}
        }};
        do_write(buffers, ec);
    }

    void unsub(string_view sid, size_t max_msgs)
    {
        boost::system::error_code ec;
        unsub(sid, max_msgs, ec);
        boost::asio::detail::throw_error(ec, "unsub");
    }

    void unsub(string_view sid, size_t max_msgs, boost::system::error_code& ec)
    {
        ec.assign(0, ec.category());
        char num_data[detail::max_chars<size_t>()];
        auto num_size = detail::write_dec(num_data, max_msgs);
        std::array<boost::asio::const_buffer, 5> buffers {{
            {"UNSUB ", 6},
            {sid.data(), sid.size()}, {" ", 1},
            {num_data, num_size}, {"\r\n", 2}
        }};
        do_write(buffers, ec);
    }

private:
    impl_type& impl() noexcept { return static_cast<impl_type&>(*this); }
    impl_type const& impl() const noexcept { return static_cast<impl_type const&>(*this); }

    template<class Stream,
             class HeaderContainer,
             class BodyContainer>
    bool read_from_buffer(Stream& stream,
                          basic_message<HeaderContainer, BodyContainer>& msg,
                          boost::system::error_code& ec)
    {
        bool stop = false;
        while (!stop && data_offs_ < data_size_) {
            auto pr = parser_.parse(&buffer_[data_offs_], data_size_ - data_offs_);
            data_offs_ += pr.second;
            switch (pr.first.type()) {
            case detail::input_type::unknown:
                ec = error::parser_error;
                stop = true;
                break;
            case detail::input_type::need_more:
                break;
            case detail::input_type::info:
                handle_input(ec, pr.first.template data<detail::input_type::info>());
                stop = true;
                break;
            case detail::input_type::msg:
                handle_input(ec, pr.first.template data<detail::input_type::msg>(), msg);
                stop = true;
                break;
            case detail::input_type::ping:
                handle_input(ec, pr.first.template data<detail::input_type::ping>());
                break;
            case detail::input_type::pong:
                handle_input(ec, pr.first.template data<detail::input_type::pong>());
                break;
            case detail::input_type::ok:
                if (state_ == state::wait_info_ack) {
                    state_ = state::ready;
                    stop = true;
                } else if (!verbose_) {
                    ec = error::unexpected_response;
                }
                break;
            case detail::input_type::err:
                ec = pr.first.template data<detail::input_type::err>().code;
                stop = true;
                break;
            default:
                BOOST_ASSERT_MSG(false, "Unknown input type");
            }
            stop = stop || ec;
        }
        if (!stop) stream.async_read_some(boost::asio::buffer(buffer_),
            [this, &stream, &msg, &ec](boost::system::error_code read_ec, size_t read_size) {
                if (!read_ec) {
                    data_offs_ = 0;
                    data_size_ = read_size;
                    read_from_buffer(stream, msg, ec);
                } else if (read_ec != boost::asio::error::operation_aborted && !ec) {
                    ec = read_ec;
                }
            });
        else if (timer_wait_) {
            timer_wait_ = false;
            detail::cancel_and_forward_error(timer_, ec);
        }
        return stop;
    }

    template<class Stream,
             class HeaderContainer,
             class BodyContainer>
    void read_input(Stream& stream,
                    basic_message<HeaderContainer, BodyContainer>& msg,
                    boost::system::error_code& ec,
                    boost::posix_time::time_duration dur = boost::posix_time::not_a_date_time)
    {
        timer_wait_ = false;
        if (!read_from_buffer(stream, msg, ec)) {
            if (!dur.is_not_a_date_time()) {
                timer_.expires_from_now(dur);
                timer_.async_wait([this, &ec](boost::system::error_code wait_ec) {
                    if (wait_ec != boost::asio::error::operation_aborted) {
                        if (!(ec = wait_ec))
                            ec = error::timed_out;
                        detail::cancel_and_forward_error(impl().socket(), ec);
                    }
                });
                timer_wait_ = true;
            }
            boost::system::error_code io_ec;
            stream.get_io_service().reset();
            stream.get_io_service().run(io_ec);
            if (io_ec && !ec)
                ec = io_ec;
        }
        if (ec && (&ec.category() != &error::client_errors_category() || ec.value() < error::invalid_subject)) {
            boost::system::error_code ec;
            close(ec);
        }
    }

    void do_handshake(authorization const& auth, boost::system::error_code& ec)
    {
        impl().handshake(ec);
        if (!ec) {
            std::array<boost::asio::const_buffer, 12> buffers {{
                detail::to_const_buffer("CONNECT {\"verbose\":"),
                detail::to_const_buffer(verbose_ ? "true" : "false"),
                detail::to_const_buffer(",\"user\":\""),
                detail::to_const_buffer(auth.user()),
                detail::to_const_buffer("\",\"pass\":\""),
                detail::to_const_buffer(auth.password()),
                detail::to_const_buffer("\",\"auth_token\":\""),
                detail::to_const_buffer(auth.token()),
                detail::to_const_buffer("\",\"tls_required\":"),
                detail::to_const_buffer(impl().secured() ? "true" : "false"),
                detail::to_const_buffer(",\"pedantic\":true,"
                    "\"name\":\"asio_nats_client\","
                    "\"lang\":\"C++\","
                    "\"version\":\"\","
                    "\"protocol\":0}\r\n"),
                detail::to_const_buffer("PING\r\n")
            }};
            do_write(buffers, ec);
            pong_count_ += 1;
        }
    }

    void handle_input(boost::system::error_code& ec,
                      detail::input_data<detail::input_type::info>)
    {
        if (state_ != state::wait_info) {
            ec = error::unexpected_response;
            return;
        }
        // TODO check info details
    }

    template<class HeaderContainer, class BodyContainer>
    void handle_input(boost::system::error_code& ec,
                      detail::input_data<detail::input_type::msg> msg,
                      basic_message<HeaderContainer, BodyContainer>& to_msg)
    {
        if (state_ != state::ready) {
            ec = error::unexpected_response;
            return;
        }
        detail::assign_message(to_msg, msg);
    }

    void handle_input(boost::system::error_code& ec,
                      detail::input_data<detail::input_type::ping>)
    {
        if (state_ != state::ready) {
            ec = error::unexpected_response;
            return;
        }
        boost::asio::async_write(
            impl().stream(),
            boost::asio::buffer("PONG\r\n", 6),
            [&ec](boost::system::error_code write_ec, size_t) {
                if (write_ec && write_ec != boost::asio::error::operation_aborted && !ec)
                    ec = write_ec;
            });
    }

    void handle_input(boost::system::error_code& ec,
                      detail::input_data<detail::input_type::pong>)
    {
        if (pong_count_ == 0) {
            ec = error::unexpected_response;
            return;
        }
        pong_count_ -= 1;
    }

    template<class ConstBufferSequence>
    void do_write(ConstBufferSequence const& buffers, boost::system::error_code& ec)
    {
        if (batch_buffer_) {
            auto const add_size = boost::asio::buffer_size(buffers);
            auto const old_size = batch_buffer_->size();
            batch_buffer_->resize(old_size + add_size);
            boost::asio::mutable_buffer b{batch_buffer_->data() + old_size, add_size};
            boost::asio::buffer_copy(b, buffers);
        } else {
            boost::asio::write(impl().stream(), buffers, ec);
        }
    }

    boost::asio::deadline_timer timer_;
    detail::parser parser_;
    std::vector<char> buffer_;
    boost::optional<std::vector<char>> batch_buffer_;
    size_t data_size_ = 0;
    size_t data_offs_ = 0;
    size_t pong_count_ = 0;
    state state_ = state::disconnected;
    bool verbose_:1;
    bool timer_wait_:1;
};

template<class Protocol>
class client: public basic_client<client<Protocol>>
{
    using this_type = client<Protocol>;
    using socket_type = typename Protocol::socket;

    friend basic_client<this_type>;

public:
    explicit client(boost::asio::io_service& io)
        : basic_client<this_type>{io}
        , socket_{io}
    {}

private:
    bool secured() const noexcept { return false; }
    socket_type& socket() noexcept { return socket_; }
    socket_type& stream() noexcept { return socket_; }
    socket_type const& socket() const noexcept { return socket_; }
    socket_type const& stream() const noexcept { return socket_; }

    void handshake(boost::system::error_code&) const noexcept {}

    void close(boost::system::error_code& ec)
    {
        socket_.close(ec);
    }

    socket_type socket_;
};

} // namespace nats

#ifndef NATS_CLIENT_SEPARATE_COMPILATION
#define NATS_CLIENT_INLINE inline
#include "client.ipp"
#endif

#endif
