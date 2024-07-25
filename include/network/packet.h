#ifndef _PACKET_H
#define _PACKET_H

#include <stdlib.h>
#include "utils/expandargs.h"
#include "types.h"

#define HEADROOM_SIZE 10

typedef struct packet_buffer_st {
    uint8_t *base;
    uint8_t *data;
    size_t capacity;
    size_t data_len;
} packet_buffer;

void init_packet_buffer(packet_buffer *pk_buf, size_t size);

size_t write_length(packet_buffer *pk_buf, int32_t packet_length, int32_t data_length);

void write_boolean(packet_buffer *pk_buf, uint8_t value);
void write_byte(packet_buffer *pk_buf, int8_t value);
void write_ubyte(packet_buffer *pk_buf, uint8_t value);
void write_short(packet_buffer *pk_buf, int16_t value);
void write_ushort(packet_buffer *pk_buf, uint16_t value);
void write_int(packet_buffer *pk_buf, int32_t value);
void write_long(packet_buffer *pk_buf, int64_t value);
void write_float(packet_buffer *pk_buf, float value);
void write_double(packet_buffer *pk_buf, double value);
void write_varint(packet_buffer *pk_buf, int32_t value);
void write_varlong(packet_buffer *pk_buf, int64_t value);
void write_string(packet_buffer *pk_buf, const char *str);
void write_uuid(packet_buffer *pk_buf, pk_uuid uuid);
void write_bytearray(packet_buffer *pk_buf, pk_bytearray bytearray);

typedef struct {
    int32_t pid;
    packet_buffer buf;
} packet;

void free_packet(packet *p);

#define SCAN(packet_, scanned_length, ...) \
    do { \
        uint8_t *_SCAN_DATA = (packet_)->buf.data; \
        size_t _SCAN_OFS = scanned_length; \
        size_t _SCAN_TEMP; (void)_SCAN_TEMP; \
        EVAL(REPEAT(PP_NARG(__VA_ARGS__), _READ_TYPE, __VA_ARGS__)) \
        scanned_length = _SCAN_OFS; \
    } while(0) \

#define _READ_TYPE(arg_name) \
    (_Generic(arg_name, \
        pk_boolean  :   __READ_BOOLEAN(arg_name), \
        pk_varint   :   __READ_VARINT(arg_name), \
        default     :   __READ_TYPE(arg_name) \
    )); \


#define __READ_TYPE(arg_name) \
    _Generic(arg_name, \
        pk_byte     :   __READ_BYTE(arg_name), \
        pk_ubyte    :   __READ_UBYTE(arg_name), \
        pk_int      :   __READ_INT(arg_name), \
        pk_long     :   __READ_LONG(arg_name), \
        pk_float    :   __READ_FLOAT(arg_name), \
        pk_double   :   __READ_DOUBLE(arg_name), \
        pk_string   :   __READ_STRING(arg_name) \
    ) \

#define __READ_BOOLEAN(arg_name) \
    ( \
        _pread_boolean(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 1 \
    ) \

#define __READ_BYTE(arg_name) \
    ( \
        _pread_byte(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 1 \
    ) \

#define __READ_UBYTE(arg_name) \
    ( \
        _pread_ubyte(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 1 \
    ) \

#define __READ_INT(arg_name) \
    ( \
        _pread_int(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 4 \
    ) \

#define __READ_LONG(arg_name) \
    ( \
        _pread_long(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 8 \
    ) \

#define __READ_VARINT(arg_name) \
    (_SCAN_OFS += _pread_varint(_SCAN_DATA + _SCAN_OFS, &arg_name))

#define __READ_FLOAT(arg_name) \
    ( \
        _pread_float(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 4 \
    ) \

#define __READ_DOUBLE(arg_name) \
    ( \
        _pread_double(_SCAN_DATA + _SCAN_OFS, &arg_name), \
        _SCAN_OFS += 8 \
    ) \

#define __READ_STRING(arg_name) \
    (_SCAN_OFS += _pread_string(_SCAN_DATA + _SCAN_OFS, &arg_name))

/*
 * The MARSHAL() macro writes the provided packet type elements into the packet.
 * Note that the init_packet_buffer() function within this macro will call malloc()
 * to allocate memory for the packet's buffer. Therefore, if the packet buffer
 * passed in already has allocated space, using MARSHAL() will result in a memory leak.
 */
#define MARSHAL(packet_, ...) \
    do { \
        pk_varint PID_ = FIRST_ARG(__VA_ARGS__); \
        packet_.pid = (PID_); \
        packet_buffer *BUF_P = &(packet_.buf); \
        init_packet_buffer(BUF_P, 64); \
        EVAL(REPEAT(PP_NARG(__VA_ARGS__), _WRITE_TYPE, __VA_ARGS__)) \
    } while(0) \

#define _WRITE_TYPE(value) \
    (_Generic(value, \
        pk_varint   :   write_varint, \
        default     :   __WRITE_TYPE(value) \
    )(BUF_P, value)); \

#define __WRITE_TYPE(value) \
    (_Generic(value, \
        pk_short    :   write_short,     \
        pk_ushort   :   write_ushort,    \
        pk_int      :   write_int,       \
        pk_long     :   write_long,      \
        pk_float    :   write_float,     \
        pk_double   :   write_double,    \
        pk_string   :   write_string,    \
        pk_uuid     :   write_uuid,      \
        pk_bytearray:   write_bytearray  \
    )) \

#define SEND(conn, ...) \
    do { \
        packet _SEND_TEMP_PACKET; \
        MARSHAL(_SEND_TEMP_PACKET, (pk_varint)__VA_ARGS__); \
        send_packet(conn, &_SEND_TEMP_PACKET); \
        free(_SEND_TEMP_PACKET.buf.base); \
    } while (0) \

#endif /* _PACKET_H */