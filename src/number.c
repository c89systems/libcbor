#define _GNU_SOURCE
#include "number.h"
#if defined(__APPLE__)
#include <xlocale.h>
#endif
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int c89_number_read(const char *text, size_t length, c89cbor_token *token,
                    locale_t locale) {
  uint64_t value = 0;
  size_t i, first;
  unsigned int digit;
  int negative, decimal = 0, nonzero = 0, saved_errno;
  char *end;
  double number;
  fenv_t environment;
  if (text == NULL || length == 0 || token == NULL)
    return C89CBOR_INVALID;
  memset(token, 0, sizeof(*token));
  negative = text[0] == '-';
  first = negative ? 1 : 0;
  if (first == length)
    return C89CBOR_MALFORMED;
  for (i = first; i < length; ++i) {
    if (text[i] == '.' || text[i] == 'e' || text[i] == 'E')
      decimal = 1;
  }
  if (!decimal) {
    if (negative && length == sizeof("-18446744073709551616") - 1u &&
        memcmp(text, "-18446744073709551616", length) == 0) {
      token->type = C89CBOR_NEGATIVE;
      token->argument = UINT64_MAX;
      return C89CBOR_OK;
    }
    for (i = first; i < length; ++i) {
      if (text[i] < '0' || text[i] > '9')
        return C89CBOR_MALFORMED;
      digit = (unsigned int)(text[i] - '0');
      if (value > (UINT64_MAX - digit) / 10u)
        return C89CBOR_LIMIT;
      value = value * 10u + digit;
    }
    token->type = negative && value != 0 ? C89CBOR_NEGATIVE : C89CBOR_UINT;
    token->argument = negative && value != 0 ? value - 1u : value;
    return C89CBOR_OK;
  }
  for (i = first; i < length && text[i] != 'e' && text[i] != 'E'; ++i) {
    if (text[i] >= '1' && text[i] <= '9')
      nonzero = 1;
  }
  saved_errno = errno;
  if (fegetenv(&environment) != 0)
    return C89CBOR_UNSUPPORTED;
  if (fesetround(FE_TONEAREST) != 0) {
    (void)fesetenv(&environment);
    return C89CBOR_UNSUPPORTED;
  }
  errno = 0;
  number = strtod_l(text, &end, locale);
  (void)fesetenv(&environment);
  errno = saved_errno;
  if (end != text + length)
    return C89CBOR_MALFORMED;
  if (number > DBL_MAX || number < -DBL_MAX || (nonzero && number == 0))
    return C89CBOR_LIMIT;
  return c89cbor_float64_set(NULL, token, number);
}

int c89_number_double(const c89cbor_token *token, double *value) {
  uint32_t bits;
  float number;
  unsigned int exponent, fraction;
  double result;
  if (token == NULL || value == NULL)
    return C89CBOR_INVALID;
  if (token->type == C89CBOR_FLOAT64) {
    if (((token->argument >> 52u) & 2047u) == 2047u)
      return C89CBOR_UNSUPPORTED;
    return c89cbor_float64_get(NULL, token, value);
  }
  if (token->type == C89CBOR_FLOAT32) {
    if (((token->argument >> 23u) & 255u) == 255u ||
        sizeof(number) != sizeof(bits) || FLT_MANT_DIG != 24)
      return C89CBOR_UNSUPPORTED;
    bits = (uint32_t)token->argument;
    memcpy(&number, &bits, sizeof(number));
    *value = number;
    return C89CBOR_OK;
  }
  if (token->type != C89CBOR_FLOAT16)
    return C89CBOR_UNSUPPORTED;
  exponent = (unsigned int)((token->argument >> 10u) & 31u);
  fraction = (unsigned int)(token->argument & 1023u);
  if (exponent == 31u)
    return C89CBOR_UNSUPPORTED;
  result = exponent == 0
               ? ldexp((double)fraction, -24)
               : ldexp((double)(1024u + fraction), (int)exponent - 25);
  *value = (token->argument & 32768u) != 0 ? -result : result;
  return C89CBOR_OK;
}

static size_t format_unsigned(uint64_t value, char *text) {
  char digits[20];
  size_t count = 0, i;
  do {
    digits[count++] = (char)('0' + value % 10u);
    value /= 10u;
  } while (value != 0);
  for (i = 0; i < count; ++i)
    text[i] = digits[count - i - 1u];
  text[count] = '\0';
  return count;
}

int c89_number_format(const c89cbor_token *token, char text[64], size_t *length,
                      locale_t locale) {
  double number;
  int status, count, saved_errno;
  locale_t previous;
  fenv_t environment;
  if (length != NULL)
    *length = 0;
  if (token == NULL || text == NULL || length == NULL)
    return C89CBOR_INVALID;
  if (token->type == C89CBOR_UINT) {
    *length = format_unsigned(token->argument, text);
    return C89CBOR_OK;
  }
  if (token->type == C89CBOR_NEGATIVE) {
    if (token->argument == UINT64_MAX) {
      strcpy(text, "-18446744073709551616");
      *length = sizeof("-18446744073709551616") - 1u;
    } else {
      text[0] = '-';
      *length = 1u + format_unsigned(token->argument + 1u, text + 1);
    }
    return C89CBOR_OK;
  }
  status = c89_number_double(token, &number);
  if (status != 0)
    return status;
  saved_errno = errno;
  if (fegetenv(&environment) != 0)
    return C89CBOR_UNSUPPORTED;
  if (fesetround(FE_TONEAREST) != 0) {
    (void)fesetenv(&environment);
    return C89CBOR_UNSUPPORTED;
  }
  previous = uselocale(locale);
  if (previous == (locale_t)0) {
    (void)fesetenv(&environment);
    return C89CBOR_UNSUPPORTED;
  }
  count = snprintf(text, 64, "%.17g", number);
  (void)uselocale(previous);
  (void)fesetenv(&environment);
  errno = saved_errno;
  if (count <= 0 || count > 60)
    return C89CBOR_LIMIT;
  *length = (size_t)count;
  if (strchr(text, '.') == NULL && strchr(text, 'e') == NULL &&
      strchr(text, 'E') == NULL) {
    text[(*length)++] = '.';
    text[(*length)++] = '0';
    text[*length] = '\0';
  }
  return C89CBOR_OK;
}
