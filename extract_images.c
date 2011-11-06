/*
 * Author: John O'Connor
 * Copyright (C) 2011
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "glib.h"
#include "nids.h"

#include "openssl/sha.h"

GHashTable *response_buffers = NULL;
GHashTable *jpegs = NULL;

#define OUTPUT_DIR "out/"
#define DEFAULT_IMAGE_BUFLEN 60000
#define MAX_IMAGE_SIZE 150000

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

static const char default_filter[] = "tcp port 80";
static const char http_get_image[] =
    "GET /teams/team9/team_services_Team9.jpg";

static const char jpeg_start_magic[] = { 0xFF, 0xD8 };
static const char jpeg_end_magic[] = { 0xFF, 0xD9 };

static guint nimages = 0, nignored = 0, nduplicates = 0;

#define HASH_ADDR(a) GUINT_TO_POINTER(hash_addr(&a))

void
g_string_freex(gpointer str)
{
    g_string_free((GString *) str, TRUE);
}

void
sha256_free(gpointer slice)
{
    g_slice_free1(SHA256_DIGEST_LENGTH + 1, slice);
}

guchar *
sha256(void *buf, gsize len)
{
    SHA256_CTX ctx;
    guchar *hash;

    hash = g_slice_alloc(SHA256_DIGEST_LENGTH + 1);
    memset(hash, 0, SHA256_DIGEST_LENGTH + 1);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (guchar *) buf, len);
    SHA256_Final(hash, &ctx);
    return hash;
}

guint
memhash(void *mem, size_t n)
{
    assert(n > 0);

    const guchar *p = (guchar *) mem;
    guint hash = *p;

    while (--n > 0) {
        hash *= 33;
        hash += *++p;
    }
    return hash;
}

guint
hash_addr(struct tuple4 * addr)
{
    return memhash(addr, sizeof(*addr));
}

inline gboolean
check_image_request(gpointer buf, gsize len)
{
    return memmem(buf, len, http_get_image,
                  sizeof(http_get_image) - 1) != NULL;
}

void
process_partial_http_request(struct tcp_stream *tcp)
{
    struct half_stream *s = &tcp->server;

    if (s->offset == 0 && check_image_request(s->data, s->count)) {
        GString *buffer = g_string_sized_new(DEFAULT_IMAGE_BUFLEN);
        g_hash_table_insert(response_buffers, HASH_ADDR(tcp->addr), buffer);
        g_message("Found image request from %s to %s\n",
                  int_ntoa(tcp->addr.saddr), int_ntoa(tcp->addr.daddr));
    }
    s->collect--;
}

void
process_partial_http_response(struct tcp_stream *tcp)
{
    GString *buffer;
    struct half_stream *c = &tcp->client;

    buffer = g_hash_table_lookup(response_buffers, HASH_ADDR(tcp->addr));
    if (buffer == NULL) {
        return;
    }
    buffer = g_string_append_len(buffer, c->data, c->count_new);
}

void
extract_image(struct tcp_stream *tcp)
{
    GString *buffer;
    guchar *hash;
    gchar *offset, *image, filename[FILENAME_MAX];
    gsize content_len, image_size;
    GError *error = NULL;

    buffer = g_hash_table_lookup(response_buffers, HASH_ADDR(tcp->addr));
    if (buffer == NULL) {
        return;
    }
    offset =
        (gchar *) memmem(buffer->str, buffer->len, "Content-Length: ", 16);
    if (offset == NULL) {
        goto end;
    }
    content_len = strtol(offset + 16, NULL, 10);
    image = (gchar *) memmem(buffer->str, buffer->len, "\r\n\r\n", 4);
    if (image == NULL) {
        goto end;
    }
    image += 4;
    if (image - buffer->str > buffer->len) {
        goto end;
    }
    image_size = buffer->len - (image - buffer->str);
    if (content_len > MAX_IMAGE_SIZE || image_size > MAX_IMAGE_SIZE) {
        g_warning("Ignoring image exceeding %d bytes, image_size = %lu.",
                  MAX_IMAGE_SIZE, MAX(image_size, content_len));
        goto end;
    }
    if (content_len > image_size) {
        g_warning("Ignoring partial image, %lu bytes, Content-Length: %lu",
                  image_size, content_len);
        nignored++;
        goto end;
    }
    if (memcmp(image, jpeg_start_magic, 2) != 0) {
        /* corrupt jpeg data */
        gchar *end;
        g_message("Attempting to recover corrupt jpeg");
        image = memmem(image, image_size, jpeg_start_magic, 2);
        if (image == NULL) {
            g_warning("Cannot find jpeg start magic");
            goto end;
        }
        end = memmem(image, image_size, jpeg_end_magic, 2);
        if (end == NULL) {
            g_warning("Cannot find jpeg end magic");
            goto end;
        }
        image_size = end - image;
    }
    hash = sha256(image, image_size);
    if (g_hash_table_lookup_extended(jpegs, hash, NULL, NULL)) {
        nduplicates++;
        sha256_free(hash);
        g_message("Skipping duplicate image");
        goto end;
    }
    g_hash_table_insert(jpegs, hash, NULL);

    snprintf(filename, sizeof(filename), OUTPUT_DIR "%d.jpg", nimages++);
    g_message("Writing image with size %lu\n", MIN(content_len, image_size));
    g_file_set_contents(filename, image, MIN(content_len, image_size), &error);
    if (error) {
        g_critical("Error writing image: %s", error->message);
        g_error_free(error);
    }
 end:
    g_hash_table_remove(response_buffers, HASH_ADDR(tcp->addr));
}

void
tcp_callback(struct tcp_stream *tcp, void **unused)
{
    switch (tcp->nids_state) {
    case NIDS_JUST_EST:
        if (tcp->addr.dest == 80) {
            tcp->client.collect++;
            tcp->server.collect++;
        }
        break;
    case NIDS_CLOSE:
    case NIDS_RESET:
    case NIDS_TIMED_OUT:
    case NIDS_EXITING:
        if (tcp->client.count_new) {
            process_partial_http_response(tcp);
        }
        extract_image(tcp);
        break;
    case NIDS_DATA:
        if (tcp->server.count_new) {
            process_partial_http_request(tcp);
        }
        if (tcp->client.count_new) {
            process_partial_http_response(tcp);
        }
        break;
    default:
        g_assert(FALSE);
    }
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap_file> <filter>\n", argv[0]);
        exit(1);
    }
    if (argc == 3) {
        nids_params.pcap_filter = argv[2];
    }
    else {
        nids_params.pcap_filter = (char *)default_filter;
    }
    nids_params.filename = argv[1];
    if (!nids_init()) {
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);
    }

    response_buffers = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, g_string_freex);
    jpegs = g_hash_table_new_full(g_str_hash, g_str_equal, sha256_free, NULL);

    nids_register_tcp(tcp_callback);
    nids_run();

    g_hash_table_destroy(response_buffers);
    g_hash_table_destroy(jpegs);

    return 0;
}
