#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "htparse.h"

static int
_msg_begin(htparser * p) {
    int * count = (int *)htparser_get_userdata(p);
    (*count)++;
    return 0;
}

static int
_msg_complete(htparser * p) {
    int * count = (int *)htparser_get_userdata(p);
    (*count)++;
    return 0;
}

htparse_hooks hooks = {
    .on_msg_begin    = _msg_begin,
    .method          = NULL,
    .scheme          = NULL,
    .host            = NULL,
    .port            = NULL,
    .path            = NULL,
    .args            = NULL,
    .uri             = NULL,
    .on_hdrs_begin   = NULL,
    .hdr_key         = NULL,
    .hdr_val         = NULL,
    .hostname        = NULL,
    .on_hdrs_complete= NULL,
    .on_new_chunk    = NULL,
    .on_chunk_complete= NULL,
    .on_chunks_complete= NULL,
    .body            = NULL,
    .on_msg_complete = _msg_complete
};

void
test_basic_get() {
    htparser * p = htparser_new();
    int count = 0;
    const char * data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

    htparser_init(p, htp_type_request);
    htparser_set_userdata(p, &count);

    size_t len = strlen(data);
    size_t nread = htparser_run(p, &hooks, data, len);
    assert(nread == len);
    assert(htparser_get_error(p) == htparse_error_none);
    assert(htparser_get_method(p) == htp_method_GET);
    assert(count == 2); /* begin and complete */

    free(p);
    printf("test_basic_get passed\n");
}

void
test_chunked_post() {
    htparser * p = htparser_new();
    int count = 0;
    const char * data = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "5\r\nhello\r\n0\r\n\r\n";

    htparser_init(p, htp_type_request);
    htparser_set_userdata(p, &count);

    size_t nread = htparser_run(p, &hooks, data, strlen(data));
    assert(nread == strlen(data));
    assert(htparser_get_error(p) == htparse_error_none);
    assert(htparser_get_method(p) == htp_method_POST);

    free(p);
    printf("test_chunked_post passed\n");
}

void
test_malformed_request() {
    htparser * p = htparser_new();
    int count = 0;
    const char * data = "GET / HTTP/1.1\r\nInvalid Header\r\n\r\n";

    htparser_init(p, htp_type_request);
    htparser_set_userdata(p, &count);

    size_t nread = htparser_run(p, &hooks, data, strlen(data));
    /* llhttp is strict, it should fail on "Invalid Header" (missing colon) */
    assert(htparser_get_error(p) != htparse_error_none);

    free(p);
    printf("test_malformed_request passed\n");
}

int
main() {
    test_basic_get();
    test_chunked_post();
    test_malformed_request();
    printf("All parser tests passed!\n");
    return 0;
}
