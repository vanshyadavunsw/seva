#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "../src/utils.h"

#define TEST_MODULE_NAME "utils"

void log_test_start(void) {
    printf("Testing module %s\n", TEST_MODULE_NAME);
}

void log_success(char *name) {
    printf("[PASS] test \"%s\" succeeded.\n", name);
}

void test_parse_int_normal();
void test_parse_int_negative();
void test_parse_int_invalid();
void test_close_to_max_min();
void test_parse_int_overflow();

int main(void) {
    log_test_start();

    test_parse_int_normal();
    test_parse_int_negative();
    test_parse_int_invalid();
    test_close_to_max_min();
    test_parse_int_overflow();

    printf("ALL OK\n");

    return 0;
}

void test_parse_int_normal() {
    struct test {
        char *bytes;
        int32_t expected;
    } cases[] = {
        { "1284271", 1284271 },
        { "4912918", 4912918 },
        { "1", 1 },
        { "512", 512 },
        { "0", 0 },
        { "000", 0 },
    };

    int32_t num;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int res = mem_dec_to_i32(
            (uint8_t *) cases[i].bytes,
            strlen(cases[i].bytes), &num
        );
        assert(res == 0);
        assert(num == cases[i].expected);
    }

    log_success("test parse int from bytes normal");
}

void test_parse_int_negative() {
    struct test {
        char *bytes;
        int32_t expected;
    } cases[] = {
        { "-1284271", -1284271 },
        { "-4912918", -4912918 },
        { "-1", -1 },
        { "-512", -512 },
        { "-999999", -999999 },
    };

    int32_t num;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int res = mem_dec_to_i32(
            (uint8_t *) cases[i].bytes,
            strlen(cases[i].bytes), &num
        );
        assert(res == 0);
        assert(num == cases[i].expected);
    }

    log_success("test parse int from bytes negative");
}

void test_parse_int_invalid() {
    char *cases[] = {
        "-",
        "491 2918",
        " ",
        "24fq811",
        "ffffff",
        "\t  ",
        "",
        "  211245",
        "214214   "
    };

    int32_t num;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int res = mem_dec_to_i32(
            (uint8_t *) cases[i],
            strlen(cases[i]), &num
        );
        assert(res == -1);
    }

    log_success("test parse int from bytes invalid cases");
}

void test_close_to_max_min() {
    struct test {
        char *bytes;
        int32_t expected;
    } cases[] = {
        { "2147483647", INT32_MAX },
        { "-2147483648", INT32_MIN },
    };

    int32_t num;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int res = mem_dec_to_i32(
            (uint8_t *) cases[i].bytes,
            strlen(cases[i].bytes), &num
        );
        assert(res == 0);
        assert(num == cases[i].expected);
    }

    log_success("test parse int from bytes close to INT32_MAX and INT32_MIN");
}

void test_parse_int_overflow() {
    char *cases[] = {
        "2147483648",
        "-2147483649",
        "2147483649",
        "-2147483650",
        "99241924912941294",
        "-99241924912941294",
    };

    int32_t num;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int res = mem_dec_to_i32(
            (uint8_t *) cases[i],
            strlen(cases[i]), &num
        );
        assert(res == -1);
    }

    log_success("test parse int from bytes overflow");
}


