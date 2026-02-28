#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif

#include "htparse.h"
#include "llhttp.h"
#include "evhtp-internal.h"

#if '\n' != '\x0a' || 'A' != 65
#error "You have somehow found a non-ASCII host. We can't build here."
#endif

struct htparser {
    llhttp_t       llparser;
    llhttp_settings_t llsettings;
    htpparse_error error;
    htparse_hooks * hooks;

    htp_type   type;
    htp_scheme scheme;
    htp_method method;

    unsigned char multipart;
    uint64_t      content_len;
    uint64_t      orig_content_len;
    uint64_t      bytes_read;
    uint64_t      total_bytes_read;

    void * userdata;

    /* For URL parsing */
    const char * scheme_offset;
    size_t       scheme_len;
    const char * host_offset;
    size_t       host_len;
    const char * port_offset;
    size_t       port_len;
    const char * path_offset;
    size_t       path_len;
    const char * args_offset;
    size_t       args_len;

    int last_was_content_type;
};

static const char * errstr_map[] = {
    "htparse_error_none",
    "htparse_error_too_big",
    "htparse_error_invalid_method",
    "htparse_error_invalid_requestline",
    "htparse_error_invalid_schema",
    "htparse_error_invalid_protocol",
    "htparse_error_invalid_version",
    "htparse_error_invalid_header",
    "htparse_error_invalid_chunk_size",
    "htparse_error_invalid_chunk",
    "htparse_error_invalid_state",
    "htparse_error_user",
    "htparse_error_status",
    "htparse_error_generic"
};

static const char * method_strmap[] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "MKCOL",
    "COPY",
    "MOVE",
    "OPTIONS",
    "PROPFIND",
    "PROPPATCH",
    "LOCK",
    "UNLOCK",
    "TRACE",
    "CONNECT",
    "PATCH",
};

/* Callback wrappers */

static int
ll_on_message_begin(llhttp_t * p) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->on_msg_begin) {
        if (h->hooks->on_msg_begin(h) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

static int
ll_on_url(llhttp_t * p, const char * at, size_t len) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->uri) {
        if (h->hooks->uri(h, at, len) != 0) {
            return HPE_USER;
        }
    }

    /* Rough URL parsing to satisfy scheme/host/port/path/args hooks if present */
    const char * cur = at;
    const char * end = at + len;

    const char * colon_slash_slash = NULL;
    for (size_t i = 0; i + 2 < len; i++) {
        if (at[i] == ':' && at[i+1] == '/' && at[i+2] == '/') {
            colon_slash_slash = at + i;
            break;
        }
    }
    if (colon_slash_slash) {
        h->scheme_offset = at;
        h->scheme_len = colon_slash_slash - at;
        if (h->hooks && h->hooks->scheme) {
            if (h->hooks->scheme(h, h->scheme_offset, h->scheme_len) != 0) return HPE_USER;
        }
        cur = colon_slash_slash + 3;
    }

    const char * slash = memchr(cur, '/', end - cur);
    const char * question = memchr(cur, '?', end - cur);

    const char * host_end = slash ? slash : (question ? question : end);
    h->host_offset = cur;
    const char * colon = memchr(cur, ':', host_end - cur);
    if (colon) {
        h->host_len = colon - cur;
        h->port_offset = colon + 1;
        h->port_len = host_end - (colon + 1);
    } else {
        h->host_len = host_end - cur;
        h->port_offset = NULL;
        h->port_len = 0;
    }

    if (h->hooks && h->hooks->host && h->host_len > 0) {
        if (h->hooks->host(h, h->host_offset, h->host_len) != 0) return HPE_USER;
    }
    if (h->hooks && h->hooks->port && h->port_len > 0) {
        if (h->hooks->port(h, h->port_offset, h->port_len) != 0) return HPE_USER;
    }

    if (slash) {
        h->path_offset = slash;
        if (question) {
            h->path_len = question - slash;
        } else {
            h->path_len = end - slash;
        }
    } else {
        h->path_offset = NULL;
        h->path_len = 0;
    }

    if (h->hooks && h->hooks->path && h->path_offset) {
        if (h->hooks->path(h, h->path_offset, h->path_len) != 0) return HPE_USER;
    }

    if (question) {
        h->args_offset = question + 1;
        h->args_len = end - (question + 1);
        if (h->hooks && h->hooks->args) {
            if (h->hooks->args(h, h->args_offset, h->args_len) != 0) return HPE_USER;
        }
    } else {
        h->args_offset = NULL;
        h->args_len = 0;
    }

    return HPE_OK;
}

static int
ll_on_header_field(llhttp_t * p, const char * at, size_t len) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->hdr_key) {
        if (h->hooks->hdr_key(h, at, len) != 0) {
            return HPE_USER;
        }
    }
    /* Check for multipart */
    if (len == 12 && !strncasecmp(at, "Content-Type", 12)) {
        h->last_was_content_type = 1;
    } else {
        h->last_was_content_type = 0;
    }
    return HPE_OK;
}

static int
ll_on_header_value(llhttp_t * p, const char * at, size_t len) {
    htparser * h = p->data;

    if (h->last_was_content_type) {
        if (len >= 9 && !strncasecmp(at, "multipart", 9)) {
            h->multipart = 1;
        }
        h->last_was_content_type = 0;
    }

    if (h->hooks && h->hooks->hdr_val) {
        if (h->hooks->hdr_val(h, at, len) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

static int
ll_on_headers_complete(llhttp_t * p) {
    htparser * h = p->data;
    h->content_len = p->content_length;
    h->orig_content_len = p->content_length;

    if (h->hooks && h->hooks->on_hdrs_complete) {
        int res = h->hooks->on_hdrs_complete(h);
        if (res < 0) return HPE_USER;
    }
    return HPE_OK;
}

static int
ll_on_body(llhttp_t * p, const char * at, size_t len) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->body) {
        if (h->hooks->body(h, at, len) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

static int
ll_on_message_complete(llhttp_t * p) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->on_msg_complete) {
        if (h->hooks->on_msg_complete(h) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

static int
ll_on_chunk_header(llhttp_t * p) {
    htparser * h = p->data;
    h->content_len = p->content_length;
    if (h->hooks && h->hooks->on_new_chunk) {
        if (h->hooks->on_new_chunk(h) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

static int
ll_on_chunk_complete(llhttp_t * p) {
    htparser * h = p->data;
    if (h->hooks && h->hooks->on_chunk_complete) {
        if (h->hooks->on_chunk_complete(h) != 0) {
            return HPE_USER;
        }
    }
    return HPE_OK;
}

/* API functions */

htpparse_error
htparser_get_error(htparser * p) {
    llhttp_errno_t err = llhttp_get_errno(&p->llparser);
    if (err == HPE_OK) return htparse_error_none;
    if (err == HPE_USER) return htparse_error_user;
    return htparse_error_generic;
}

const char *
htparser_get_strerror(htparser * p) {
    return llhttp_errno_name(llhttp_get_errno(&p->llparser));
}

unsigned int
htparser_get_status(htparser * p) {
    return p->llparser.status_code;
}

int
htparser_should_keep_alive(htparser * p) {
    return llhttp_should_keep_alive(&p->llparser);
}

htp_type
htparser_get_type(htparser * p) {
    return p->type;
}

htp_scheme
htparser_get_scheme(htparser * p) {
    return p->scheme;
}

htp_method
htparser_get_method(htparser * p) {
    switch (p->llparser.method) {
        case HTTP_GET:     return htp_method_GET;
        case HTTP_HEAD:    return htp_method_HEAD;
        case HTTP_POST:    return htp_method_POST;
        case HTTP_PUT:     return htp_method_PUT;
        case HTTP_DELETE:  return htp_method_DELETE;
        case HTTP_MKCOL:   return htp_method_MKCOL;
        case HTTP_COPY:    return htp_method_COPY;
        case HTTP_MOVE:    return htp_method_MOVE;
        case HTTP_OPTIONS: return htp_method_OPTIONS;
        case HTTP_PROPFIND: return htp_method_PROPFIND;
        case HTTP_PROPPATCH: return htp_method_PROPPATCH;
        case HTTP_LOCK:    return htp_method_LOCK;
        case HTTP_UNLOCK:  return htp_method_UNLOCK;
        case HTTP_TRACE:   return htp_method_TRACE;
        case HTTP_CONNECT: return htp_method_CONNECT;
        case HTTP_PATCH:   return htp_method_PATCH;
        default:           return htp_method_UNKNOWN;
    }
}

const char *
htparser_get_methodstr_m(htp_method meth) {
    if (meth >= htp_method_UNKNOWN) {
        return NULL;
    }
    return method_strmap[meth];
}

const char *
htparser_get_methodstr(htparser * p) {
    return llhttp_method_name(p->llparser.method);
}

void
htparser_set_major(htparser * p, unsigned char major) {
    p->llparser.http_major = major;
}

void
htparser_set_minor(htparser * p, unsigned char minor) {
    p->llparser.http_minor = minor;
}

unsigned char
htparser_get_major(htparser * p) {
    return p->llparser.http_major;
}

unsigned char
htparser_get_minor(htparser * p) {
    return p->llparser.http_minor;
}

unsigned char
htparser_get_multipart(htparser * p) {
    return p->multipart;
}

void *
htparser_get_userdata(htparser * p) {
    return p->userdata;
}

void
htparser_set_userdata(htparser * p, void * ud) {
    p->userdata = ud;
}

uint64_t
htparser_get_content_pending(htparser * p) {
    return p->content_len;
}

uint64_t
htparser_get_content_length(htparser * p) {
    return p->orig_content_len;
}

uint64_t
htparser_get_total_bytes_read(htparser * p) {
    return p->total_bytes_read;
}

void
htparser_init(htparser * p, htp_type type) {
    llhttp_type_t ltype = (type == htp_type_request) ? HTTP_REQUEST : HTTP_RESPONSE;

    llhttp_settings_init(&p->llsettings);
    p->llsettings.on_message_begin = ll_on_message_begin;
    p->llsettings.on_url = ll_on_url;
    p->llsettings.on_header_field = ll_on_header_field;
    p->llsettings.on_header_value = ll_on_header_value;
    p->llsettings.on_headers_complete = ll_on_headers_complete;
    p->llsettings.on_body = ll_on_body;
    p->llsettings.on_message_complete = ll_on_message_complete;
    p->llsettings.on_chunk_header = ll_on_chunk_header;
    p->llsettings.on_chunk_complete = ll_on_chunk_complete;

    llhttp_init(&p->llparser, ltype, &p->llsettings);

    p->llparser.data = p;
    p->type = type;
    p->error = htparse_error_none;
    p->total_bytes_read = 0;
    p->content_len = 0;
    p->orig_content_len = 0;
    p->multipart = 0;
}

htparser *
htparser_new(void) {
    htparser * p = malloc(sizeof(htparser));
    if (p) {
        memset(p, 0, sizeof(htparser));
    }
    return p;
}

size_t
htparser_run(htparser * p, htparse_hooks * hooks, const char * data, size_t len) {
    if (p == NULL) return 0;
    p->hooks = hooks;
    p->bytes_read = 0;

    if (len == 0 || data == NULL) {
        llhttp_errno_t err = llhttp_finish(&p->llparser);
        if (err != HPE_OK) {
            p->error = htparse_error_generic;
        }
        return 0;
    }

    llhttp_errno_t err = llhttp_execute(&p->llparser, data, len);

    const char * error_pos = llhttp_get_error_pos(&p->llparser);
    size_t nread;

    if (error_pos == NULL) {
        nread = len;
    } else {
        nread = error_pos - data;
    }

    p->bytes_read = nread;
    p->total_bytes_read += nread;

    if (err != HPE_OK && err != HPE_PAUSED) {
        return nread;
    }

    return nread;
}
