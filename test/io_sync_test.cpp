#include <boost/asio/ip/tcp.hpp>
#include <asio_nats/client.hpp>
#include <cassert>

template<class Proto>
void test_no_messages(nats::client<Proto>& client, int sec = 2)
{
    nats::message_view msg;
    boost::system::error_code ec;
    auto const t1 = boost::posix_time::microsec_clock::universal_time();
    client.read_for(msg, boost::posix_time::seconds{sec}, ec);
    auto const t2 = boost::posix_time::microsec_clock::universal_time();
    assert(ec == nats::error::timed_out);
    assert((t2 - t1).seconds() >= sec);
    assert(msg.subject.empty());
    assert(msg.sid.empty());
    assert(msg.reply_to.empty());
    assert(msg.payload.empty());
}

template<class Proto>
void test_io(nats::client<Proto>& client)
{
    boost::system::error_code ec;

    // sub to mailformed subject
    client.sub("test.", "1");
    {
        nats::message_void msg;
        client.read(msg, ec);
        assert(ec == nats::error::invalid_subject);
    }

    client.sub("test_view", "0");
    client.sub("test_string", "1");

    // trying to write not started batch
    client.batch_write(ec);
    assert(ec == nats::error::batch_not_ready);

    client.batch_begin();
    client.sub("test_vector", "2");
    client.sub("test_string_vector", "3");
    client.batch_write();

    // pub to mailformed subject
    client.pub("test.", "test");
    {
        nats::message_void msg;
        client.read(msg, ec);
        assert(ec == nats::error::invalid_subject);
    }

    client.pub("test_view", "reply_to_view", "view1");

    client.batch_begin();
    client.batch_write();

    client.batch_begin();
    client.pub("test_view", "", "view2");
    client.pub("test_string", "reply_to_string", "string");
    client.pub("test_vector", "vector");
    client.pub("test_string_vector", "string_vector");
    client.batch_write();

    {
        nats::message_view msg;
        client.read_for(msg, boost::posix_time::seconds{10});
        assert(msg.subject == "test_view");
        assert(msg.sid == "0");
        assert(msg.reply_to == "reply_to_view");
        assert(msg.payload == "view1");
        client.read(msg);
        assert(msg.subject == "test_view");
        assert(msg.sid == "0");
        assert(msg.reply_to == ""); // !!!
        assert(msg.payload == "view2");
    }
    {
        nats::message msg;
        client.read(msg);
        assert(msg.subject == "test_string");
        assert(msg.sid == "1");
        assert(msg.reply_to == "reply_to_string");
        assert(msg.payload == "string");
    }
    {
        nats::basic_message<std::vector<char>, std::vector<char>> msg;
        client.read(msg);
        assert((msg.subject == std::vector<char>{'t','e','s','t','_','v','e','c','t','o','r'}));
        assert((msg.sid == std::vector<char>{'2'}));
        assert((msg.reply_to == std::vector<char>{}));
        assert((msg.payload == std::vector<char>{'v','e','c','t','o','r'}));
    }
    {
        nats::basic_message<std::string, std::vector<char>> msg;
        client.read(msg);
        assert(msg.subject == "test_string_vector");
        assert(msg.sid == "3");
        assert(msg.reply_to == "");
        assert((msg.payload == std::vector<char>{'s','t','r','i','n','g','_','v','e','c','t','o','r'}));
    }

    client.unsub("3"); // unsub from 'test_string_vector' immediately
    client.pub("test_string_vector", "string_vector");
    test_no_messages(client);

    client.batch_begin();
    client.sub("test_auto_unsub", "4");
    client.unsub("4", 3); // unsub from 'test_auto_unsub' after 3 messages
    client.batch_write();

    client.pub("test_auto_unsub", "p1");
    client.pub("test_auto_unsub", "p2");
    client.batch_begin();
    client.pub("test_auto_unsub", "p3");
    client.pub("test_auto_unsub", "p4");
    client.batch_write();

    for (auto payload: {"p1", "p2", "p3"}) {
        nats::message_view msg;
        client.read(msg);
        assert(msg.subject == "test_auto_unsub");
        assert(msg.sid == "4");
        assert(msg.payload == payload);
    }
    test_no_messages(client);
}

int main()
{
    using proto = boost::asio::ip::tcp;

    proto::endpoint const endpoint{boost::asio::ip::address_v4::loopback(), 4222};

    boost::asio::io_service io;
    boost::system::error_code ec;
    nats::message_void msg;

    // test default state
    nats::client<proto> client{io};
    assert(!client.connected());
    assert(!client.verbose());

    // connection would fail when no credentials are given
    client.connect(endpoint);
    assert(client.connected());
    client.read(msg, ec);
    assert(ec == nats::error::auth_violation);

    // connection would fail on unknown user/password
    client.connect(endpoint, {"user", "password"});
    assert(client.connected());
    client.read(msg, ec);
    assert(ec == nats::error::auth_violation);

    // connection would fail on unknown token
    client.connect(endpoint, {"token"});
    assert(client.connected());
    client.read(msg, ec);
    assert(ec == nats::error::auth_violation);

    client.connect(endpoint, {"test_user", "test_password"});
    test_io(client);
    client.close();

    // test verbose is enabled
    client.verbose(true);
    assert(client.verbose());

    // connection would fail when no credentials are given
    client.connect(endpoint, ec);
    assert(!client.connected());
    assert(ec == nats::error::auth_violation);

    // connection would fail on unknown user/password
    client.connect(endpoint, {"user", "password"}, ec);
    assert(!client.connected());
    assert(ec == nats::error::auth_violation);

    // connection would fail on unknown token
    client.connect(endpoint, {"token"}, ec);
    assert(!client.connected());
    assert(ec == nats::error::auth_violation);

    client.connect(endpoint, {"test_user", "test_password"});
    assert(client.connected());
    client.close();
    assert(!client.connected());

    client.connect(endpoint, {"test_user", "test_password"});
    test_io(client);
}