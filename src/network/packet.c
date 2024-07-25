#include "packet.h"
#include <string.h>

void
init_packet_buffer(packet_buffer *pk_buf, size_t size)
{
    pk_buf->base = malloc(size + HEADROOM_SIZE);
    pk_buf->data = pk_buf->base + HEADROOM_SIZE;  
    pk_buf->capacity = size;
    pk_buf->data_len = 0;
}

void
free_packet(packet *p)
{
    if(p->buf.base) free(p->buf.base);
    free(p);
}

size_t
write_length(packet_buffer *pk_buf, int32_t packet_length, int32_t data_length)
{
    uint8_t varint[5];
    size_t ofs1 = encode_varint(varint, data_length);
    memcpy(pk_buf->data - ofs1, varint, ofs1);
    if (packet_length == 0)
        return ofs1;
    size_t ofs2 = encode_varint(varint, packet_length);
    memcpy(pk_buf->data - ofs1 - ofs2, varint, ofs2);
    return ofs1 + ofs2;
}

#define max(a, b) \
    ({__typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b; })

static void
ensure_buf_capacity(packet_buffer *buf, size_t need)
{
    if (buf->capacity >= need)
        return;
    size_t new_capacity = max(buf->capacity << 1, need);
    buf->base = realloc(buf->base, new_capacity);
    buf->data = buf->base + HEADROOM_SIZE;
    buf->capacity = new_capacity;
}

void write_boolean(packet_buffer *pk_buf, uint8_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 1);
    encode_boolean(pk_buf->data + (pk_buf->data_len++), value);
}

void write_byte(packet_buffer *pk_buf, int8_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 1);
    encode_byte(pk_buf->data + (pk_buf->data_len++), value);
}

void write_ubyte(packet_buffer *pk_buf, uint8_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 1);
    encode_ubyte(pk_buf->data + (pk_buf->data_len++), value);
}

void write_short(packet_buffer *pk_buf, int16_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 2);
    encode_short(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 2;
}

void write_ushort(packet_buffer *pk_buf, uint16_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 2);
    encode_ushort(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 2;
}

void write_int(packet_buffer *pk_buf, int32_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 4);
    encode_int(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 4;
}

void write_long(packet_buffer *pk_buf, int64_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 8);
    encode_long(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 8;
}

void write_float(packet_buffer *pk_buf, float value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 4);
    encode_float(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 4;
}

void write_double(packet_buffer *pk_buf, double value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 8);
    encode_double(pk_buf->data + pk_buf->data_len, value);
    pk_buf->data_len += 8;
}

void write_varint(packet_buffer *pk_buf, int32_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 5);
    pk_buf->data_len += encode_varint(pk_buf->data + pk_buf->data_len, value);
}

void write_varlong(packet_buffer *pk_buf, int64_t value)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 10);
    pk_buf->data_len += encode_varlong(pk_buf->data + pk_buf->data_len, value);
}

void write_string(packet_buffer *pk_buf, const char *str)
{
    size_t str_len = strlen(str);
    ensure_buf_capacity(pk_buf, pk_buf->data_len + str_len + 5);
    pk_buf->data_len += encode_string(pk_buf->data + pk_buf->data_len, str, str_len);
}

void write_uuid(packet_buffer *pk_buf, pk_uuid uuid)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + 16);
    encode_uuid(pk_buf->data + pk_buf->data_len, uuid);
    pk_buf->data_len += 16;
}

void write_bytearray(packet_buffer *pk_buf, pk_bytearray bytearray)
{
    ensure_buf_capacity(pk_buf, pk_buf->data_len + bytearray.length + 5);
    pk_buf->data_len += encode_bytearray(pk_buf->data + pk_buf->data_len, bytearray);
}