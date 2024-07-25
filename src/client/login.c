#include "client/login.h"
#include "data/packetid.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#define PANIC(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while(0);

#define SHARED_SECRET_SIZE 16

static void handle_encryption_request(connection *conn, packet *p);
static EVP_CIPHER_CTX *init_aes_cfb8(const unsigned char *key, int enc);
static void rsa_encrypt(EVP_PKEY *pkey, const unsigned char *input, 
        size_t input_len, unsigned char *output, size_t output_len);

static void handle_set_compression(connection *conn, packet *p);
static void handle_login_success(connection *conn, packet *p);
static char * server_hash(const char *server_id, const char *shared_secret,
                          const char *pub_key, size_t pub_key_len);

int
login(client *c, const char *address, int port)
{
    connection *conn = &c->conn;

    SEND(conn,
        handshaking_serverbound_handshake,
        (pk_varint) PROTOCOL_VERSION,
        (pk_string) "localhost",
        (pk_ushort) 25565,
        (pk_varint) 2
    );
    SEND(conn,
        login_serverbound_login_start,
        (pk_string) "mccc",
        ((pk_uuid) {.x = {1, 2, 3}})
    );

    while(1)
    {
        packet p;
        recv_packet(conn, &p);
        printf("login pid: %d\n", p.pid);
        switch (p.pid)
        {
            case login_clientbound_disconnect: 
                PANIC("disconnect")
            case login_clientbound_encryption_request:
                handle_encryption_request(conn, &p);
                break;
            case login_clientbound_login_success:
                handle_login_success(conn, &p);
                free(p.buf.base);
    return 0;
            case login_clientbound_set_compression:
                handle_set_compression(conn, &p);
                break;
            default:
                fprintf(stderr, "login: undefined pid: %d\n", p.pid);
                exit(EXIT_FAILURE); 
        }
        free(p.buf.base);
    }
}


static void 
handle_encryption_request(connection *conn, packet *p)
{
    size_t scanned_bytes = 0;
    pk_string server_id;
    pk_varint public_key_length;
    pk_varint verify_token_length;
    SCAN(p, scanned_bytes, server_id, public_key_length);

    unsigned char *pub_key_DER = p->buf.data + scanned_bytes;
    EVP_PKEY *pub_key = d2i_PUBKEY(NULL, (const unsigned char **) &pub_key_DER, public_key_length);
    if (pub_key == NULL)
        PANIC("d2i_PUBKEY()")   

    scanned_bytes += public_key_length;
    SCAN(p, scanned_bytes, verify_token_length);

    unsigned char shared_secret[SHARED_SECRET_SIZE];
    if (RAND_bytes(shared_secret, sizeof(shared_secret)) != 1)
        PANIC("RAND_bytes()");

    #define ENCRYPTED_SIZE 128
    unsigned char encrypted_shared_secret[ENCRYPTED_SIZE];
    unsigned char encrypted_verify_token[ENCRYPTED_SIZE];

    rsa_encrypt( pub_key, shared_secret, sizeof(shared_secret),
                 encrypted_shared_secret, ENCRYPTED_SIZE );
    rsa_encrypt( pub_key, p->buf.data + scanned_bytes, verify_token_length,
                 encrypted_verify_token, ENCRYPTED_SIZE );
    EVP_PKEY_free(pub_key);   

    scanned_bytes += verify_token_length;
    pk_boolean should_auth;
    SCAN(p, scanned_bytes, should_auth);

    if (should_auth) {
        char *hash_str = server_hash( server_id,
                                      (const char *)shared_secret,
                                      (const char *)pub_key_DER, public_key_length );
        printf("hash: %s\n", hash_str);
    }
    free(server_id);

    SEND(conn,
        login_serverbound_encryption_response,
        ((pk_bytearray) {.arr = encrypted_shared_secret, .length = ENCRYPTED_SIZE}),
        ((pk_bytearray) {.arr = encrypted_verify_token, .length = ENCRYPTED_SIZE})
    );

    conn->dec_ctx = init_aes_cfb8(shared_secret, 0);
    conn->enc_ctx = init_aes_cfb8(shared_secret, 1);
}

static EVP_CIPHER_CTX *
init_aes_cfb8(const unsigned char *key, int enc) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        PANIC("Error creating context")
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cfb8(), NULL, key, key, enc) != 1)
        PANIC("Error initializing AES/CFB8")
    return ctx;
}

static void 
rsa_encrypt(EVP_PKEY *pkey, const unsigned char *input, size_t input_len,
            unsigned char *output, size_t output_len) 
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        PANIC("Error creating context");
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        PANIC("Error initializing encryption");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        PANIC("Error setting RSA padding");
    size_t outlen = output_len;
    if (EVP_PKEY_encrypt(ctx, output, &outlen, input, input_len) <= 0)
        PANIC("Error encrypting data");
    if (outlen != output_len) 
        PANIC("Unexpected encrypted length");
    EVP_PKEY_CTX_free(ctx);
}


static void 
handle_set_compression(connection *conn, packet *p) 
{
    size_t scanned_bytes = 0;
    pk_varint threshold;
    SCAN(p, scanned_bytes, threshold);
    set_threshold(conn, threshold);
}

static void 
handle_login_success(connection *conn, packet *p) {
    // TODO: scan packet

    SEND(conn, login_serverbound_login_acknowledged);
    return;
}

static char *
server_hash(const char *server_id, const char *shared_secret,
            const char *pub_key, size_t pub_key_len)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        PANIC("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1)
        PANIC("EVP_DigestInit_ex failed");
 
    if (EVP_DigestUpdate(mdctx, server_id, strlen(server_id)) != 1)
        PANIC("EVP_DigestUpdate failed");
    
    if (EVP_DigestUpdate(mdctx, shared_secret, SHARED_SECRET_SIZE) != 1)
        PANIC("EVP_DigestUpdate failed");

    if (EVP_DigestUpdate(mdctx, pub_key, pub_key_len) != 1)
        PANIC("EVP_DigestUpdate failed");

    uint8_t *hash = malloc(64);
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
        PANIC("EVP_DigestFinal_ex failed"); 

    int negative = (hash[0] & 0x80) == 0x80;
    if (negative) {
        int carry = 1;
        for (int i = hash_len - 1; i >= 0; i--) {
            hash[i] = ~hash[i];
            if (carry) {
                carry = hash[i] == 0xFF;
                hash[i]++;
            }
        }
    }

    char hex_str[hash_len * 2 + 1]; 
         hex_str[hash_len * 2] = '\0';
    for (size_t i = 0; i < hash_len; ++i) 
        sprintf(&hex_str[i * 2], "%02x", hash[i]);
    free(hash);

    size_t start = 0;
    while (hex_str[start] == '0' && start < hash_len * 2 - 1)
        start++;

    size_t resLen = strlen(hex_str + start) + (negative ? 2 : 1);
    char *res = malloc(resLen);

    if (negative) {
        res[0] = '-';
        strcpy(res + 1, hex_str + start);
    } else {
        strcpy(res, hex_str + start);
    }

    return res;
}