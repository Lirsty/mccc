#include "types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void encode_boolean(uint8_t *dest, uint8_t value)
{
    dest[0] = (value) ? 0x01 : 0x00;
}

uint8_t read_boolean(uint8_t *data)
{
    return data[0];
}

void _pread_boolean(uint8_t *data, void *ret)
{
    *(uint8_t *)ret = data[0];
}

void encode_byte(uint8_t *dest, int8_t value)
{
    dest[0] = (uint8_t) value;
}

int8_t read_byte(uint8_t *data)
{
    return (int8_t) data[0];
}

void _pread_byte(uint8_t *data, void *ret) 
{
    *(int8_t *)ret = (int8_t)data[0];
}

void encode_ubyte(uint8_t *dest, uint8_t value) 
{
    dest[0] = value;
}

uint8_t read_ubyte(uint8_t *data) 
{
    return data[0];
}

void _pread_ubyte(uint8_t *data, void *ret) {
    *(uint8_t *)ret = data[0];
}

void encode_short(uint8_t *dest, int16_t value) 
{
    dest[0] = (uint8_t)((value >> 8) & 0xFF);
    dest[1] = (uint8_t)(value & 0xFF);
}

int16_t read_short(uint8_t *data)  
{
    return (int16_t)((data[0] << 8) | data[1]);
}

void _pread_short(uint8_t *data, void *ret) 
{
    *(int16_t *)ret = (int16_t)((data[0] << 8) | data[1]);
}

void encode_ushort(uint8_t *dest, uint16_t value) 
{
    dest[0] = (uint8_t)((value >> 8) & 0xFF);
    dest[1] = (uint8_t)(value & 0xFF);
}

uint16_t read_ushort(uint8_t *data) 
{
    return (uint16_t)((data[0] << 8) | data[1]);
}

void _pread_ushort(uint8_t *data, void *ret) 
{
    *(uint16_t *)ret = (uint16_t)((data[0] << 8) | data[1]);
}

void encode_int(uint8_t *dest, int32_t value) 
{
    dest[0] = (uint8_t)((value >> 24) & 0xFF);
    dest[1] = (uint8_t)((value >> 16) & 0xFF);
    dest[2] = (uint8_t)((value >> 8) & 0xFF);
    dest[3] = (uint8_t)(value & 0xFF);
}

int32_t read_int(uint8_t *data) 
{
    return (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
}

void _pread_int(uint8_t *data, void *ret) 
{
    *(int32_t *)ret = (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
}

void encode_long(uint8_t *dest, int64_t value) 
{
    dest[0] = (uint8_t)((value >> 56) & 0xFF);
    dest[1] = (uint8_t)((value >> 48) & 0xFF);
    dest[2] = (uint8_t)((value >> 40) & 0xFF);
    dest[3] = (uint8_t)((value >> 32) & 0xFF);
    dest[4] = (uint8_t)((value >> 24) & 0xFF);
    dest[5] = (uint8_t)((value >> 16) & 0xFF);
    dest[6] = (uint8_t)((value >> 8) & 0xFF);
    dest[7] = (uint8_t)(value & 0xFF);
}


int64_t read_long(uint8_t *data) 
{
    return (int64_t)((uint64_t)data[0] << 56 | (uint64_t)data[1] << 48 | (uint64_t)data[2] << 40 | 
                     (uint64_t)data[3] << 32 | (uint64_t)data[4] << 24 | (uint64_t)data[5] << 16 |
                     (uint64_t)data[6] << 8  | (uint64_t)data[7]);
}

void _pread_long(uint8_t *data, void *ret) 
{
    *(int64_t *)ret = (int64_t)((uint64_t)data[0] << 56 | (uint64_t)data[1] << 48 | (uint64_t)data[2] << 40 |
                                (uint64_t)data[3] << 32 | (uint64_t)data[4] << 24 | (uint64_t)data[5] << 16 |
                                (uint64_t)data[6] << 8  | (uint64_t)data[7]);
}


void encode_float(uint8_t *dest, float value) 
{
    uint32_t int_value;
    memcpy(&int_value, &value, sizeof(int_value));
    encode_int(dest, int_value);
}

float read_float(uint8_t *data) 
{
    uint32_t int_value = read_int(data);
    float value;
    memcpy(&value, &int_value, sizeof(value));
    return value;
}

void _pread_float(uint8_t *data, void *ret) 
{
    uint32_t int_value = read_int(data);
    memcpy(ret, &int_value, sizeof(float));
}

void encode_double(uint8_t *dest, double value) 
{
    uint64_t int_value;
    memcpy(&int_value, &value, sizeof(int_value));
    encode_long(dest, int_value);
}

double read_double(uint8_t *data) 
{
    uint64_t int_value = read_long(data);
    double value;
    memcpy(&value, &int_value, sizeof(value));
    return value;
}

void _pread_double(uint8_t *data, void *ret)
{
    uint64_t int_value = read_long(data);
    memcpy(ret, &int_value, sizeof(double));
}

#define SEGMENT_BITS 0x7F
#define CONTINUE_BIT 0x80

size_t encode_varint(uint8_t *dest, int32_t value) 
{
    uint32_t v = (uint32_t) value;
    size_t offset = 0;
    while (1)
    {
        if ((v & ~SEGMENT_BITS) == 0)
        {
            dest[offset++] = v;
            break;
        }

        dest[offset++] = (v & SEGMENT_BITS) | CONTINUE_BIT;
        v >>= 7;
    }
    return offset;
}


int32_t read_varint(uint8_t *data, size_t *ret_varint_size) 
{
    int32_t value = 0;
    size_t offset = 0;
    int position = 0;
    uint8_t currentByte;

    do {
        currentByte = data[offset++];
        value |= (currentByte & SEGMENT_BITS) << position;

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 32) 
        {
            perror("VarInt is too big.");
            exit(EXIT_FAILURE);
        }
    } while (1);

    *ret_varint_size = offset; 
    return value;
}

size_t _pread_varint(uint8_t *data, void *ret)
{
    int32_t value = 0;
    size_t offset = 0;
    int position = 0;
    uint8_t currentByte;

    do {
        currentByte = data[offset++];
        value |= (currentByte & SEGMENT_BITS) << position;

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 32) 
        {
            perror("VarInt is too big.");
            exit(EXIT_FAILURE);
        }
    } while (1);

    *(int32_t *)ret = value; 
    return offset;
}


size_t encode_varlong(uint8_t *dest, int64_t value) 
{
    uint64_t v = (uint64_t) value;
    size_t offset= 0;
    while (1)
    {
        if ((v & ~((int64_t)SEGMENT_BITS)) == 0)
        {
            dest[offset++] = v;
            break;
        }

        dest[offset++] = (v & SEGMENT_BITS) | CONTINUE_BIT;
        v >>= 7;
    }
    return offset;
}


int64_t read_varlong(uint8_t *data, size_t *ret_varlong_size)
{
    int64_t value = 0;
    size_t offset = 0;
    int position = 0;
    uint8_t currentByte;

    do {
        currentByte = data[offset++];
        value |= (int64_t)(currentByte & SEGMENT_BITS) << position;

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 64)
        {
            perror("VarLong is too big.");
            exit(EXIT_FAILURE);
        }
    } while (1);
    *ret_varlong_size = offset;
    return value;
}

size_t _pread_varlong(uint8_t *data, void *ret)
{
    int64_t value = 0;
    size_t offset = 0;
    int position = 0;
    uint8_t currentByte;

    do {
        currentByte = data[offset++];
        value |= (int64_t)(currentByte & SEGMENT_BITS) << position;

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 64)
        {
            perror("VarLong is too big.");
            exit(EXIT_FAILURE);
        }
    } while (1);

    *(int64_t *)ret = value;
    return offset;
}


size_t encode_string(uint8_t *dest, const char *str, size_t str_len)
{
    size_t ret = encode_varint(dest, str_len);
    memcpy(dest + ret, str, str_len);
    return ret + str_len;
}   


char *read_string(uint8_t *data, size_t *ret_read_length)
{
    size_t varint_size;
    int32_t str_len = read_varint(data, &varint_size);
    char *str = malloc(str_len + 1);
    if (str == NULL) 
    {
        perror("read string");
        exit(EXIT_FAILURE);
    }
    memcpy(str, data + varint_size, str_len);
    str[str_len] = '\0';
    *ret_read_length = varint_size + str_len;
    return str;
}

size_t _pread_string(uint8_t *data, void *ret)
{
    size_t varint_size;
    int32_t str_len = read_varint(data, &varint_size);
    char *str = malloc(str_len + 1);
    if (str == NULL) 
    {
        perror("read string");
        exit(EXIT_FAILURE);
    }
    memcpy(str, data + varint_size, str_len);
    str[str_len] = '\0';
    *(char **)ret = str;
    return varint_size + str_len;
}


void encode_uuid(uint8_t *dest, pk_uuid uuid)
{
    memcpy(dest, uuid.x, sizeof(uuid.x));
}


pk_uuid read_uuid(uint8_t *data) 
{
    pk_uuid uuid;
    memcpy(uuid.x, data, 16);
    return uuid;
}

void _pread_uuid(uint8_t *data, void *ret)
{
    memcpy(((pk_uuid *)ret)->x, data, 16);
}

size_t encode_bytearray(uint8_t *dest, pk_bytearray bytearray)
{
    size_t ofs = encode_varint(dest, bytearray.length);
    memcpy(dest + ofs, bytearray.arr, bytearray.length);
    return ofs + bytearray.length;
}

pk_bytearray read_bytearray(uint8_t *data, size_t *ret_read_length)
{
    int32_t arr_len;
    size_t ofs = _pread_varint(data, &arr_len);
    uint8_t *array = malloc(arr_len);
    memcpy(array, data + ofs, arr_len);
    *ret_read_length = ofs + arr_len;
    return (pk_bytearray){.arr = array, .length = arr_len};
}

size_t _pread_bytearray(uint8_t *data, void *ret)
{
    int32_t arr_len;
    size_t ofs = _pread_varint(data, &arr_len);
    uint8_t *array = malloc(arr_len);
    memcpy(array, data + ofs, arr_len);
    *(pk_bytearray *)ret = (pk_bytearray){.arr = array, .length = arr_len}; 
    return ofs + arr_len;
}