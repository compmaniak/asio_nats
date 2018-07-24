#include <asio_nats/client.hpp>
#include <cassert>

using namespace nats;

template<size_t N>
struct test_case{};

void test_parsed_data(detail::input_data<detail::input_type::info> d, test_case<1>)
{
    assert(d.server_info == "info\r text\r");
}

void test_parsed_data(detail::input_data<detail::input_type::info> d, test_case<2>)
{
    assert(d.server_info == "");
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<1>)
{
    assert(d.msg == "error\r text\r");
    assert(d.code == error::protocol_error);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<2>)
{
    assert(d.msg == "");
    assert(d.code == error::protocol_error);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<3>)
{
    assert(d.msg == "'Unknown Protocol Operation'");
    assert(d.code == error::protocol_error);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<4>)
{
    assert(d.msg == "'Attempted To Connect To Route Port' ");
    assert(d.code == error::connect_to_route_port);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<5>)
{
    assert(d.msg == "'Authorization Violation'");
    assert(d.code == error::auth_violation);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<6>)
{
    assert(d.msg == "'Authorization Timeout'");
    assert(d.code == error::auth_timeout);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<7>)
{
    assert(d.msg == "'Invalid Client Protocol'");
    assert(d.code == error::invalid_protocol);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<8>)
{
    assert(d.msg == "'Maximum Control Line Exceeded'");
    assert(d.code == error::control_line_exceeded);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<9>)
{
    assert(d.msg == "'Parser Error'");
    assert(d.code == error::server_parser_error);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<10>)
{
    assert(d.msg == "'Secure Connection - TLS Required'");
    assert(d.code == error::not_secured);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<11>)
{
    assert(d.msg == "'Stale Connection'");
    assert(d.code == error::stale_connection);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<12>)
{
    assert(d.msg == "'Maximum Connections Exceeded'");
    assert(d.code == error::connections_exceeded);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<13>)
{
    assert(d.msg == "'Slow Consumer'");
    assert(d.code == error::slow_consumer);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<14>)
{
    assert(d.msg == "'Maximum Payload Violation'");
    assert(d.code == error::payload_too_big);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<15>)
{
    assert(d.msg == "'Invalid Subject'");
    assert(d.code == error::invalid_subject);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<16>)
{
    assert(d.msg == "'Permissions Violation for Subscription to 123'");
    assert(d.code == error::sub_not_allowed);
}

void test_parsed_data(detail::input_data<detail::input_type::err> d, test_case<17>)
{
    assert(d.msg == "'Permissions Violation for Publish to 456'");
    assert(d.code == error::pub_not_allowed);
}

void test_parsed_data(detail::input_data<detail::input_type::msg> d, test_case<1>)
{
    assert(d.subject == "subject");
    assert(d.sid == "sid");
    assert(d.reply_to == "reply-to");
    assert(d.payload == "payload");
}

void test_parsed_data(detail::input_data<detail::input_type::msg> d, test_case<2>)
{
    assert(d.subject == "subject");
    assert(d.sid == "sid");
    assert(d.reply_to == "");
    assert(d.payload == "payload");
}

void test_parsed_data(detail::input_data<detail::input_type::msg> d, test_case<3>)
{
    assert(d.subject == "\rsubject");
    assert(d.sid == "sid");
    assert(d.reply_to == "");
    assert(d.payload == "");
}

template<detail::input_type T, size_t N>
void test_parsed_data(detail::input_data<T> d, test_case<N>)
{
    struct empty_struct {};
    assert(sizeof(d) == sizeof(empty_struct));
}

detail::parser p;

template<detail::input_type T, size_t N>
void test_parse_all_in_memory(string_view src)
{
    auto pr = p.parse(src.data(), src.size());
    assert(pr.first.type() == T);
    assert(pr.second == src.size());
    test_parsed_data(pr.first.data<T>(), test_case<N>{});
}

template<detail::input_type T, size_t N>
void test_parse_fragmented(string_view src)
{
    while (src.size() > 1) {
        auto pr = p.parse(src.data(), 1);
        assert(pr.first.type() == detail::input_type::need_more);
        assert(pr.second == 1);
        src.remove_prefix(1);
    }
    auto pr = p.parse(src.data(), 1);
    assert(pr.first.type() == T);
    assert(pr.second == 1);
    test_parsed_data(pr.first.data<T>(), test_case<N>{});
}

template<detail::input_type T, size_t N>
void test_parse(string_view src)
{
    test_parse_all_in_memory<T, N>(src);
    test_parse_fragmented<T, N>(src);
}

template<detail::input_type T, size_t N>
void test_parse(std::initializer_list<string_view> srcs)
{
    for (auto src: srcs)
        test_parse<T, N>(src);
}

void test_parse_failed(std::initializer_list<string_view> srcs)
{
    for (auto src: srcs) {
        auto pr = p.parse(src.data(), src.size());
        assert(pr.first.type() == detail::input_type::unknown);
    }
}

int main()
{
    test_parse<detail::input_type::msg, 1>({
        "MSG subject sid reply-to 7\r\npayload\r\n",
        "mSG subject sid reply-to 7\r\npayload\r\n",
        "msG subject sid reply-to 7\r\npayload\r\n",
        "msg subject sid reply-to 7\r\npayload\r\n",
        "msg \tsubject sid reply-to 7\r\npayload\r\n",
        "msg \tsubject \tsid reply-to 7\r\npayload\r\n",
        "msg \tsubject \tsid reply-to 7 \t\r\npayload\r\n"});
    test_parse<detail::input_type::msg, 2>("MSG subject sid 7\r\npayload\r\n");
    test_parse<detail::input_type::msg, 3>("MSG \rsubject sid 0\r\n\r\n");

    test_parse_all_in_memory<detail::input_type::need_more, 2>("MSG subject sid 7\r\n");
    {
        detail::parser tmp{std::move(p)};
        p = std::move(tmp);
        p = std::move(p);
    }
    test_parse_all_in_memory<detail::input_type::msg, 2>("payload\r\n");

    test_parse_all_in_memory<detail::input_type::need_more, 2>("MSG subject sid 7\r\n");
    test_parse_all_in_memory<detail::input_type::need_more, 2>("");
    test_parse_all_in_memory<detail::input_type::need_more, 2>("pay");
    test_parse_all_in_memory<detail::input_type::msg, 2>("load\r\n");

    test_parse<detail::input_type::ok, 1>({
        "+OK\r\n",
        "+oK\r\n",
        "+ok\r\n"});

    test_parse<detail::input_type::err, 1>({
        "-ERR error\r text\r\r\n",
        "-eRR error\r text\r\r\n",
        "-erR error\r text\r\r\n",
        "-err \t error\r text\r\r\n"});
    test_parse<detail::input_type::err, 2>({
        "-err \r\n",
        "-err \t \r\n"});
    test_parse<detail::input_type::err, 3>("-ERR 'Unknown Protocol Operation'\r\n");
    test_parse<detail::input_type::err, 4>("-ERR 'Attempted To Connect To Route Port' \r\n");
    test_parse<detail::input_type::err, 5>("-ERR 'Authorization Violation'\r\n");
    test_parse<detail::input_type::err, 6>("-ERR 'Authorization Timeout'\r\n");
    test_parse<detail::input_type::err, 7>("-ERR 'Invalid Client Protocol'\r\n");
    test_parse<detail::input_type::err, 8>("-ERR 'Maximum Control Line Exceeded'\r\n");
    test_parse<detail::input_type::err, 9>("-ERR 'Parser Error'\r\n");
    test_parse<detail::input_type::err, 10>("-ERR 'Secure Connection - TLS Required'\r\n");
    test_parse<detail::input_type::err, 11>("-ERR 'Stale Connection'\r\n");
    test_parse<detail::input_type::err, 12>("-ERR 'Maximum Connections Exceeded'\r\n");
    test_parse<detail::input_type::err, 13>("-ERR 'Slow Consumer'\r\n");
    test_parse<detail::input_type::err, 14>("-ERR 'Maximum Payload Violation'\r\n");
    test_parse<detail::input_type::err, 15>("-ERR 'Invalid Subject'\r\n");
    test_parse<detail::input_type::err, 16>("-ERR 'Permissions Violation for Subscription to 123'\r\n");
    test_parse<detail::input_type::err, 17>("-ERR 'Permissions Violation for Publish to 456'\r\n");

    test_parse<detail::input_type::ping, 1>({
        "PING\r\n",
        "pING\r\n",
        "piNG\r\n",
        "pinG\r\n",
        "ping\r\n"});

    test_parse<detail::input_type::pong, 1>({
        "PONG\r\n",
        "pONG\r\n",
        "poNG\r\n",
        "ponG\r\n",
        "pong\r\n"});

    test_parse<detail::input_type::info, 1>({
        "INFO info\r text\r\r\n",
        "iNFO info\r text\r\r\n",
        "inFO info\r text\r\r\n",
        "infO info\r text\r\r\n",
        "info \t info\r text\r\r\n"});
    test_parse<detail::input_type::info, 2>({
        "info \r\n",
        "info \t \r\n"});

    test_parse_failed({
        "a",
        "mm",
        "mss",
        "msgg",
        "msg a b c d 5\r\n",
        "msg a 5\r\n",
        "msg a b c\r\n",
        "msg a b c 7\r\r\npayload\r\n",
        "msg a b c 7\r\npayloadX\r\n",
        "msg a b c 7\r\npayload\rX",
        "+E",
        "+OO",
        "+Okk",
        "+Ok\r\r",
        "-O",
        "-Ee",
        "-Ere",
        "-Errr",
        "PP",
        "poo",
        "ponn",
        "pongg",
        "pong\r\r",
        "pii",
        "pinn",
        "pingg",
        "ping\r\r",
        "ii",
        "inn",
        "inff",
        "infoo"
    });
}