#ifndef NATS_SECURED_CLIENT_HPP
#define NATS_SECURED_CLIENT_HPP

#include "client.hpp"
#include <boost/asio/ssl.hpp>

namespace nats
{

template<class Protocol>
class secured_client: public basic_client<secured_client<Protocol>>
{
    using this_type = secured_client<Protocol>;
    using socket_type = typename Protocol::socket;
    using stream_type = boost::asio::ssl::stream<socket_type&>;

    friend basic_client<this_type>;

public:
    explicit secured_client(boost::asio::io_service& io)
        : basic_client<this_type>{io}
        , context_{boost::asio::ssl::context::tlsv12}
        , socket_{io}
        , stream_{socket_, context_}
    {}

private:
    bool secured() const noexcept { return true; }
    socket_type& socket() noexcept { return socket_; }
    stream_type& stream() noexcept { return stream_; }
    socket_type const& socket() const noexcept { return socket_; }
    stream_type const& stream() const noexcept { return stream_; }

    void handshake(boost::system::error_code& ec)
    {
        stream_.handshake(stream_type::client, ec);
    }

    void close(boost::system::error_code& ec)
    {
        boost::system::error_code tmp_ec;
        stream_.shutdown(tmp_ec);
        socket_.close(ec);
        stream_.~stream_type();
        new (&stream_) stream_type{socket_, context_};
    }

    boost::asio::ssl::context context_;
    socket_type socket_;
    stream_type stream_;
};

} // namespace nats

#endif