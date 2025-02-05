#ifndef ABNF_H
#define ABNF_H

#include <stdint.h>

static inline int is_digit(uint8_t c) {
    return (c >= '0' && c <= '9');
}

static inline int is_alpha(uint8_t c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int is_tchar(uint8_t c) {
    if (is_digit(c) || is_alpha(c)) return 1;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&':
        case '\'': case '*': case '+': case '-': case '.':
        case '^': case '_': case '`': case '|': case '~':
            return 1;
        default:
            return 0;
    }
}

/* check if a byte (octet) is unreserved under the URI scheme*/
static inline int is_unreserved(uint8_t c) {
    if (is_digit(c) || is_alpha(c)) return 1;
    switch (c) {
        case '-': case '.': case '_': case '~':
            return 1 ;
        default:
            return 0;
    }
}

/* check if a byte (octet) is a sub delimiter under the URI scheme*/
static inline int is_sub_delim(uint8_t c) {
    switch (c) {
        case '!': case '$': case '&': case '\'':
        case '(': case ')': case '*': case '+':
        case ',': case ';': case '=':
            return 1;
        default:
            return 0;
    }
}

static inline int is_hex_dig(uint8_t c) {
    return is_digit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static inline int is_vchar(uint8_t c) {
    return c >= 0x21 && c <= 0x7E;
}

static inline int is_ows(uint8_t c) {
    return c == 0x20 || c == 0x09;
}

static inline int is_obs_text(uint8_t c) {
    return c >= 0x80 && c <= 0xFF;
}

#endif
