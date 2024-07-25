#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t pk_boolean;
typedef int8_t pk_byte;
typedef uint8_t pk_ubyte;
typedef int16_t pk_short;
typedef uint16_t pk_ushort; 
typedef int32_t pk_int;
typedef int64_t pk_long;
typedef int32_t pk_varint;
typedef int64_t pk_varlong;
typedef float pk_float;
typedef double pk_double;
typedef char * pk_string;
typedef struct { uint8_t x[16]; } pk_uuid;
typedef struct { uint8_t *arr; size_t length; } pk_bytearray;


void encode_boolean(uint8_t *dest, uint8_t value);
void encode_byte(uint8_t *dest, int8_t value);
void encode_ubyte(uint8_t *dest, uint8_t value);
void encode_short(uint8_t *dest, int16_t value);
void encode_ushort(uint8_t *dest, uint16_t value);
void encode_int(uint8_t *dest, int32_t value);
void encode_long(uint8_t *dest, int64_t value);
void encode_float(uint8_t *dest, float value);
void encode_double(uint8_t *dest, double value);
size_t encode_varint(uint8_t *dest, int32_t value);
size_t encode_varlong(uint8_t *dest, int64_t value);
size_t encode_string(uint8_t *dest, const char *str, size_t str_len);
void encode_uuid(uint8_t *dest, pk_uuid uuid);
size_t encode_bytearray(uint8_t *dest, pk_bytearray bytearray);

uint8_t read_boolean(uint8_t *data);
int8_t read_byte(uint8_t *data);
uint8_t read_ubyte(uint8_t *data);
int16_t read_short(uint8_t *data);
uint16_t read_ushort(uint8_t *data);
int32_t read_int(uint8_t *data);
int64_t read_long(uint8_t *data);
float read_float(uint8_t *data);
double read_double(uint8_t *data);
int32_t read_varint(uint8_t *data, size_t *ret_varint_size);
int64_t read_varlong(uint8_t *data, size_t *ret_varlong_size);
char *read_string(uint8_t *data, size_t *ret_read_length);
pk_uuid read_uuid(uint8_t *data);
pk_bytearray read_bytearray(uint8_t *data, size_t *ret_read_length);


void _pread_boolean(uint8_t *data, void *ret);
void _pread_byte(uint8_t *data, void *ret);
void _pread_ubyte(uint8_t *data, void *ret);
void _pread_short(uint8_t *data, void *ret);
void _pread_ushort(uint8_t *data, void *ret);
void _pread_int(uint8_t *data, void *ret);
void _pread_long(uint8_t *data, void *ret);
void _pread_float(uint8_t *data, void *ret);
void _pread_double(uint8_t *data, void *ret);
size_t _pread_varint(uint8_t *data, void *ret);
size_t _pread_varlong(uint8_t *data, void *ret);
size_t _pread_string(uint8_t *data, void *ret);
void _pread_uuid(uint8_t *data, void *ret);
size_t _pread_bytearray(uint8_t *data, void *ret);

#endif /* _TYPES_H */