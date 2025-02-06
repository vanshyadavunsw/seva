#include "../src/http.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define TEST_MODULE_NAME "http"

void log_test_start() {
    printf("Testing module %s\n", TEST_MODULE_NAME);
}

void log_success(char *name) {
    printf("[PASS] test \"%s\" succeeded.\n", name);
}

void test_parse_rqline_simple();
void test_parse_rqline_root();
void test_parse_rqline_double_seg();
void test_parse_target_asterisk();
void test_parse_target_invalid();
void test_target_complicated();
void test_parse_target_invalid_percent();
void test_invalid_methods();
void test_complex_paths();
void test_query_parameters();
void test_percent_encoding();

void test_basic_header();
void test_basic_header_2();
void test_header_whitespace();
void test_invalid_headers();
void test_header_edge_cases();
void test_header_case_nonsensitive();
void test_header_duplicate_key_diff_val();
void test_header_dup_key_dup_val();

int main() {
    log_test_start();

    test_parse_rqline_simple();
    test_parse_rqline_root();
    test_parse_rqline_double_seg();
    test_parse_target_asterisk();
    test_parse_target_invalid();
    test_target_complicated();
    test_parse_target_invalid_percent();
    test_invalid_methods();
    test_complex_paths();
    test_query_parameters();
    test_percent_encoding();

    test_basic_header();
    test_basic_header_2();
    test_header_whitespace();
    test_invalid_headers();
    test_header_edge_cases();
    test_header_case_nonsensitive();
    test_header_duplicate_key_diff_val();
    test_header_dup_key_dup_val();

    printf("ALL OK\n");

    return 0;
}

// Request-line and target parsing test suite

void test_parse_rqline_simple() {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST /lorem/ipsum/dol HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 3);

    assert(memcmp(r->target->segments[0]->bytes, "lorem", 5) == 0);
    assert(memcmp(r->target->segments[1]->bytes, "ipsum", 5) == 0);
    assert(memcmp(r->target->segments[2]->bytes, "dol", 3) == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse request line simple");
}

void test_parse_rqline_double_seg() {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST // HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 2);

    assert(r->target->segments[0]->bytes == NULL);
    assert(r->target->segments[0]->length == 0);

    assert(r->target->segments[1]->bytes == NULL);
    assert(r->target->segments[1]->length == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("target is '//'");
}

void test_parse_rqline_root() {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST / HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 1);

    assert(r->target->segments[0]->bytes == NULL);
    assert(r->target->segments[0]->length == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse request line with target as root");
}

void test_parse_target_asterisk() {
    struct HttpRequest *r = http_request_init();
    char *rqline = "CONNECT * HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 1);

    assert(r->target->segments == NULL);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse asterisk form target");
}

void test_parse_target_invalid() {
    struct HttpRequest *r;
    char *lines[] = {
        "CONNECT ../something HTTP/1.1",
        "CONNECT . HTTP/1.1",
        "CONNECT  HTTP/1.1",
        "CONNECT HTTP/1.1",
        "CONNECT HTTP/1.1",
        "CONNECT HTTP/1.1",
    };

    for (int i = 0; i < (sizeof(lines) / sizeof(char *)); i++) {
        r = http_request_init();
        int res = parse_request_line(r, (uint8_t *) lines[i], strlen(lines[i]));
        assert (res < 0);
        http_request_free(r);
    }

    log_success("invalid targets");
}

void test_target_complicated() {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST /abc/def//help.php/h%65%6c%6C%6Fworld?foo=%00%FF&bar=lorem HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 5);

    assert(r->target->segments[0]->length == 3);
    assert(memcmp(r->target->segments[0]->bytes, "abc", 3) == 0);

    assert(r->target->segments[1]->length == 3);
    assert(memcmp(r->target->segments[1]->bytes, "def", 3) == 0);

    assert(r->target->segments[2]->length == 0);
    assert(r->target->segments[2]->bytes == NULL);

    assert(r->target->segments[3]->length == 8);
    assert(memcmp(r->target->segments[3]->bytes, "help.php", 8) == 0);

    assert(r->target->segments[4]->length == 10);
    assert(memcmp(r->target->segments[4]->bytes, "helloworld", 10) == 0);

    assert(r->target->query != NULL);
    assert(r->target->query_length == 16);

    uint8_t test[] = { 'f', 'o', 'o', '=', 0, 255, '&', 'b', 'a', 'r', '=', 'l', 'o', 'r', 'e', 'm' };
    assert(memcmp(r->target->query, test, 16) == 0);

    http_request_free(r);

    log_success("test target complicated with hex decoding");
}

void test_parse_target_invalid_percent() {
    struct HttpRequest *r;
    char *lines[] = {
        "CONNECT /% HTTP/1.1",
        "CONNECT //% HTTP/1.1",
        "CONNECT /%AZ HTTP/1.1",
        "CONNECT /%A/%ab HTTP/1.1",
        "CONNECT /%z3 HTTP/1.1",
        "CONNECT /%% HTTP/1.1",
        "CONNECT /%%% HTTP/1.1",
    };

    for (int i = 0; i < (sizeof(lines) / sizeof(char *)); i++) {
        r = http_request_init();
        int res = parse_request_line(r, (uint8_t *) lines[i], strlen(lines[i]));
        assert (res < 0);
        http_request_free(r);
    }

    log_success("invalid hex encodings");
}

void test_invalid_methods() {
    const char *invalid_methods[] = {
        "INVALID / HTTP/1.1",
        "Get / HTTP/1.1",
        "POST_BAD / HTTP/1.1",
        "G#T / HTTP/1.1",
        "GET@ / HTTP/1.1",
        " GET / HTTP/1.1",
        "GET  / HTTP/1.1"
    };

    for (int i = 0; i < sizeof(invalid_methods)/sizeof(char*); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)invalid_methods[i],
                                        strlen(invalid_methods[i]));
        assert(result < 0);
        http_request_free(r);
    }
    log_success("invalid HTTP methods");
}

void test_complex_paths() {
    const char *test_cases[] = {
        "GET /a/bb/ccc/dddd HTTP/1.1",
        "GET /segment//between/empty HTTP/1.1",
        "GET /multiple///slashes HTTP/1.1",
        "GET /Upper/lower/12345/-._~!$&'()*+,;=:@ HTTP/1.1",
        "GET /really/really/really/really/really/really/long/path HTTP/1.1",
        "GET /path/with./dots/../in.it HTTP/1.1"
    };

    for (int i = 0; i < sizeof(test_cases)/sizeof(char*); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i], 
                                        strlen(test_cases[i]));
        assert(result >= 0);
        assert(r->target != NULL);
        assert(r->target->is_asterisk == false);
        http_request_free(r);
    }
    log_success("complex request paths");
}

void test_query_parameters() {
    struct {
        const char *request;
        const uint8_t *expected_query;
        size_t expected_query_len;
    } test_cases[] = {
        { "GET /path?key=value HTTP/1.1", (uint8_t *) "key=value", 9 },
        { "GET /path?k1=v1&k2=v2 HTTP/1.1", (uint8_t *) "k1=v1&k2=v2", 11 },
        { "GET /path?empty= HTTP/1.1", (uint8_t *) "empty=", 6 },
        { "GET /path?=value HTTP/1.1", (uint8_t *) "=value", 6 },
        { "GET /path?&&& HTTP/1.1", (uint8_t *) "&&&", 3 },
        { "GET /path?q=a+b HTTP/1.1", (uint8_t *) "q=a+b", 5 },
    };

    for (int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i].request, 
                                        strlen(test_cases[i].request));

        assert(result >= 0);
        assert(r->target != NULL);
        assert(r->target->query != NULL);
        assert(r->target->query_length == test_cases[i].expected_query_len);
        assert(memcmp(r->target->query, test_cases[i].expected_query,
                      test_cases[i].expected_query_len) == 0);

        http_request_free(r);
    }
    log_success("query parameter parsing");
}

void test_percent_encoding() {
    struct {
        const char* request;
        bool should_succeed;
    } test_cases[] = {
        { "GET /path%20with%20spaces HTTP/1.1", true },
        { "GET /path%2F%2E%2E%2Ftraversal HTTP/1.1", true },
        { "GET /all%ff%Fe%Fa%FB%fc%FD%00 HTTP/1.1", true },
        { "GET /invalid%2 HTTP/1.1", false },
        { "GET /invalid%2g HTTP/1.1", false },
        { "GET /invalid%g2 HTTP/1.1", false },
        { "GET /truncated% HTTP/1.1", false },
        { "GET /%2 HTTP/1.1", false },
        { "GET /%2G HTTP/1.1", false },
        { "GET /%G2 HTTP/1.1", false },
    };

    for (int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i].request, 
                                      strlen(test_cases[i].request));
        assert((result >= 0) == test_cases[i].should_succeed);
        http_request_free(r);
    }
    log_success("percent encoding edge cases");
}

// Header parsing test suite

void test_basic_header() {
    struct HttpRequest *r = http_request_init();

    char *headers[] = {
        "Host: example.com",
        "Content-Length: 42",
        "Accept: text/html, application/json",
        "X-Custom-Header: some-value",
        "Connection: keep-alive"
    };

    for (int i = 0; i < sizeof(headers) / sizeof(char*); i++) {
        int result = parse_header(r, (uint8_t *) headers[i], strlen(headers[i]));
        assert(result >= 0);
    }

    assert(r->headers->nheaders == 5);

    http_request_free(r);
    log_success("basic header parsing");
}

void test_basic_header_2() {
    struct HttpRequest *r = http_request_init();

    struct {
        char *header;
        char *expected_name;
        char *expected_value;
    } cases[] = {
        { "Host: example.com", "Host", "example.com" },
        { "Content-Length: 42", "Content-Length", "42" },
        { "Accept: text/html, application/json", "Accept", "text/html, application/json" },
        { "X-Custom-Header: some-value", "X-Custom-Header", "some-value" },
        { "Connection: keep-alive", "Connection", "keep-alive" },
        { "Contains-High-Bytes: Some \x80\x81\xFF value", 
            "Contains-High-Bytes", "Some \x80\x81\xFF value" },
    };

    for (int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int result = parse_header(r, (uint8_t *) cases[i].header, strlen(cases[i].header));
        assert(result >= 0);

        struct Header *query = htable_query(r->headers, cases[i].expected_name);

        assert(query != NULL);
        assert(query->next == NULL);
        assert(strcmp(cases[i].expected_value, query->value) == 0);

        htable_query_free(query);
    }

    assert(r->headers->nheaders == sizeof(cases) / sizeof(cases[0]));

    http_request_free(r);
    log_success("more rigorous basic header case testing");
}

// test duplicates, high bytes, duplicates should come up in same search

void test_header_whitespace() {
    struct HttpRequest *r = http_request_init();

    struct {
        char *header;
        char *expected_name;
        char *expected_value;
    } cases[] = {
        { "Host:   example.com   ", "Host", "example.com" },
        { "Content-Length:42", "Content-Length", "42" },
        { "Accept:     text/html", "Accept", "text/html" },
        { "X-Header:\tvalue    ", "X-Header", "value" },
        { "Server:     seva    ", "Server", "seva" },
        { "Random-Header: \t\t  \x81wowza \t   ", "Random-Header", "\x81wowza" }
    };

    for (int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int result = parse_header(r, (uint8_t *) cases[i].header, strlen(cases[i].header));
        assert(result >= 0);

        struct Header *query = htable_query(r->headers, cases[i].expected_name);

        assert(query != NULL);
        assert(query->next == NULL);
        assert(strcmp(cases[i].expected_value, query->value) == 0);

        htable_query_free(query);
    }

    assert(r->headers->nheaders == sizeof(cases) / sizeof(cases[0]));

    http_request_free(r);
    log_success("test header whitespace parsing");
}

void test_invalid_headers() {
    struct HttpRequest *r;

    char *invalid_headers[] = {
        ":no-header-name",
        "Invalid Header: value",
        ": missing-header-name",
        "Header\tName: value",
        "@Invalid-Char: value",
        "Header: value\n",
        "Some-Header: va\rl",
        "HeaderWithoutColon",
        " WhiteSpaceInBeginning: Hi"
    };

    for (int i = 0; i < sizeof(invalid_headers) / sizeof(char *); i++) {
        r = http_request_init();
        int result = parse_header(
            r, (uint8_t *) invalid_headers[i], strlen(invalid_headers[i])
        );
        assert(result < 0);
        http_request_free(r);
    }

    log_success("invalid header detection");
}

void test_header_edge_cases() {
    struct HttpRequest *r = http_request_init();

    char *edge_headers[] = {
        "X-Empty-Value: ",
        "a: b",
        "Long-Header-Name-123456789: value",
        "Header: !\"#$%&'()*+,-./",
        "Header: 0123456789",
        "X-Header: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };

    for (int i = 0; i < sizeof(edge_headers) / sizeof(char *); i++) {
        int result = parse_header(
            r, (uint8_t *) edge_headers[i], strlen(edge_headers[i])
        );
        assert(result == PARSE_OK);
    }

    assert(r->headers->nheaders == 6);

    http_request_free(r);
    log_success("header edge cases");
}

static int count_query_result_count(struct Header *query) {
    int i = 0;
    while (query != NULL) {
        i++;
        query = query->next;
    }
    return i;
}

static bool name_exists_in_query_cs(struct Header *query, char *name) {
    while (query != NULL) {
        if (strcmp(query->name, name) == 0) return true;
        query = query->next;
    }
    return false;
}

static bool name_val_in_query_cs(struct Header *query, char *name, char *val) {
    while (query != NULL) {
        if (strcmp(query->name, name) == 0 && strcmp(query->value, val) == 0) return true;
        query = query->next;
    }
    return false;
}

void test_header_case_nonsensitive() {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147\t\t  ";
    char *dup2 = "content-length: \t\t 148\t\t";
    char *dup3 = "cOnTeNt-LeNgTh:      149   ";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup2, strlen(dup2));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup3, strlen(dup3));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");
    struct Header *current = query;

    assert(count_query_result_count(query) == 3);

    assert(name_exists_in_query_cs(query, "Content-Length"));
    assert(name_exists_in_query_cs(query, "content-length"));
    assert(name_exists_in_query_cs(query, "cOnTeNt-LeNgTh"));

    assert(name_val_in_query_cs(query, "Content-Length", "147"));
    assert(name_val_in_query_cs(query, "content-length", "148"));
    assert(name_val_in_query_cs(query, "cOnTeNt-LeNgTh", "149"));

    htable_query_free(query);
    http_request_free(r);
    log_success("duplicate non-case-sensitive");
}

void test_header_duplicate_key_diff_val() {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147";
    char *dup2 = "Content-Length: 148";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup2, strlen(dup2));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");
    struct Header *current = query;

    assert(count_query_result_count(query) == 2);

    while (current != NULL) {
        assert(strcmp(current->name, "Content-Length") == 0);
        current = current->next;
    }

    assert(name_val_in_query_cs(query, "Content-Length", "147"));
    assert(name_val_in_query_cs(query, "Content-Length", "148"));

    htable_query_free(query);
    http_request_free(r);
    log_success("header duplicate same key different value");
}

void test_header_dup_key_dup_val() {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");
    struct Header *current = query;

    assert(count_query_result_count(query) == 2);

    while (current != NULL) {
        assert(strcmp(current->name, "Content-Length") == 0);
        current = current->next;
    }

    assert(name_val_in_query_cs(query, "Content-Length", "147"));

    htable_query_free(query);
    http_request_free(r);
    log_success("header duplicate key and duplicate val");
}

