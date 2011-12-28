// ref: http://code.taobao.org/p/tengine/src/trunk/src/http/ngx_http_variables.c
//      http://code.taobao.org/p/tengine/src/trunk/src/http/modules/ngx_http_host_comment_filter_module.c
//      ngx_http_strip_filter_module.c

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t enable;
    ngx_hash_t                          types;
    ngx_array_t                        *types_keys;
} ngx_http_host_comment_conf_t;

typedef struct {
    ngx_str_t                           comment;
} ngx_http_host_comment_ctx_t;

static void *ngx_http_host_comment_create_conf(ngx_conf_t *cf);
static char *ngx_http_host_comment_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_host_comment_filter_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_host_comment_filter_commands[] = {
    { ngx_string("host_comment"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_host_comment_conf_t, enable),
      NULL },

    { ngx_string("host_comment_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_host_comment_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    ngx_null_command
};

static ngx_http_module_t ngx_http_host_comment_filter_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_http_host_comment_filter_init,   /* postconfiguration */

    NULL,                         /* create main configuration */
    NULL,                         /* init main configuration */

    NULL,                         /* create server configuration */
    NULL,                         /* merge server configuration */

    ngx_http_host_comment_create_conf,   /* create location configuration */
    ngx_http_host_comment_merge_conf     /* merge location configuration */
};

ngx_module_t  ngx_http_host_comment_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_host_comment_filter_module_ctx,     /* module context */
    ngx_http_host_comment_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_host_comment_header_filter(ngx_http_request_t *r)
{
    ngx_http_host_comment_conf_t  *conf;
    ngx_http_host_comment_ctx_t   *ctx;
    size_t len;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_host_comment_filter_module);

    if (!conf->enable // 未启用
        || r->header_only // HEAD请求
        // || r->headers_out.status == NGX_HTTP_NOT_MODIFIED
        || r != r->main // subrequest
        || r->headers_out.status == NGX_HTTP_NO_CONTENT // 无内容
        || ngx_http_test_content_type(r, &conf->types) == NULL)  // add types support
    {
        return ngx_http_next_header_filter(r);
    }

    len = sizeof("<!-- ") - 1
          + ngx_cycle->hostname.len
          + 1
          + ngx_cached_http_log_time.len
          + sizeof(" -->" CRLF) - 1;

    // 在内存池申请空间
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_host_comment_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->comment.data = ngx_pcalloc(r->pool, len);

    ngx_memcpy(ctx->comment.data, "<!-- ", sizeof("<!-- ") - 1);
    ctx->comment.len += sizeof("<!-- ") - 1;

    ngx_memcpy(ctx->comment.data + ctx->comment.len, ngx_cycle->hostname.data, ngx_cycle->hostname.len);
    ctx->comment.len += ngx_cycle->hostname.len;

    ngx_memcpy(ctx->comment.data + ctx->comment.len, " ", 1);
    ctx->comment.len ++;

    // 也可以尝试使用 ngx_cached_http_time
    ngx_memcpy(ctx->comment.data + ctx->comment.len, ngx_cached_http_log_time.data, ngx_cached_http_log_time.len);
    ctx->comment.len += ngx_cached_http_log_time.len;

    ngx_memcpy(ctx->comment.data + ctx->comment.len, " -->" CRLF, sizeof(" -->" CRLF) - 1);
    ctx->comment.len += sizeof(" -->" CRLF) - 1;

    ngx_http_set_ctx(r, ctx, ngx_http_host_comment_filter_module);

    if (r->headers_out.content_length_n != -1) {
        r->headers_out.content_length_n += len;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);

    // return NGX_HTTP_INTERNAL_SERVER_ERROR;
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_host_comment_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t             *buf;
    ngx_uint_t             last;
    ngx_chain_t           *cl, *nl;
    ngx_http_host_comment_ctx_t *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http host_comment body filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_host_comment_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
         if (cl->buf->last_buf) {
             last = 1;
             break;
         }
    }

    if (!last) {
        return ngx_http_next_body_filter(r, in);
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    nl = ngx_alloc_chain_link(r->pool);
    if (nl == NULL) {
        return NGX_ERROR;
    }

    buf->pos = ctx->comment.data;
    buf->last = buf->pos + ctx->comment.len;
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->last_buf = 1;
    buf->memory = 1;

    nl->buf = buf;
    nl->next = NULL;
    cl->next = nl;
    cl->buf->last_buf = 0; // bug, see http://code.taobao.org/p/tengine/issue/514/

    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_host_comment_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_host_comment_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_host_comment_body_filter;

    return NGX_OK;
}

static void *
ngx_http_host_comment_create_conf(ngx_conf_t *cf) {
    ngx_http_host_comment_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_host_comment_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_host_comment_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_host_comment_conf_t *prev = parent;
    ngx_http_host_comment_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys,&prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
       return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
