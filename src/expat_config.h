/* expat_config.h - Zig build configuration */

#ifndef EXPAT_CONFIG_H
#define EXPAT_CONFIG_H

/* Endianness (used by xmltok.c) */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTEORDER 4321
#else
#define BYTEORDER 1234
#endif

/* Entropy source */
#if defined(_WIN32)
/* uses rand_s() internally */
#elif defined(__linux__)
#define HAVE_GETRANDOM 1
#elif defined(__unix__) || defined(__APPLE__)
#define HAVE_ARC4RANDOM_BUF 1
#endif

#endif /* EXPAT_CONFIG_H */
