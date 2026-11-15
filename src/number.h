#ifndef C89CBOR_NUMBER_H
#define C89CBOR_NUMBER_H
#include "internal.h"
#include <locale.h>
int c89_number_read(const char *text, size_t length, c89cbor_token *token,
                    locale_t locale);
int c89_number_format(const c89cbor_token *token, char text[64], size_t *length,
                      locale_t locale);
int c89_number_double(const c89cbor_token *token, double *value);
#endif
