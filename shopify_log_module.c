// Mostly Copyright (C) Igor Sysoev
// Mostly Copyright (C) Nginx, Inc.
// Portions Copyright (C) Shopify, Inc.

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>

#include <sys/msg.h>
#include <stdint.h>

/* The log will consume a number of bytes in memory equal to the product of these two */
#define LOG_BUFFER_SLOTS  1024

/* Message Size (+ 8 for mtype) must be under the system-imposed limit */
#ifdef __APPLE__
#define MAX_MESSAGE_SIZE  2040 // Limit 2K. Can't tune SysV MQ limits to higher values without recompiling Darwin.
#else
#define MAX_MESSAGE_SIZE  65528 // Limit 64K.
#endif

#define MESSAGE_QUEUE_KEY 0xDEADC0DE

#define SVMQ_MESSAGE_TYPE 1  // mtype for SysV MQ messages. 0 is invalid.
#define LOG_ERROR_TIMEOUT 60 // Min number of seconds between printing messages that could otherwise spam the error log.

typedef struct shopify_log_op_s  shopify_log_op_t;
typedef u_char *(*shopify_log_op_run_pt) (ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
typedef size_t (*shopify_log_op_getlen_pt) (ngx_http_request_t *r, uintptr_t data);

struct shopify_log_op_s {
  size_t                      len;
  shopify_log_op_getlen_pt    getlen;
  shopify_log_op_run_pt       run;
  uintptr_t                   data;
};


typedef struct {
  ngx_str_t                   name;
  ngx_array_t                *ops;        /* array of shopify_log_op_t */
} shopify_log_fmt_t;


typedef struct {
  ngx_array_t                 formats;    /* array of shopify_log_fmt_t */
} shopify_log_main_conf_t;


typedef struct {
  ngx_array_t                *lengths;
  ngx_array_t                *values;
} shopify_log_script_t;

typedef struct {
  long mtype;
  char mtext[MAX_MESSAGE_SIZE];
} shopify_log_msg_t;

typedef struct {
  int                         msqid;
  pthread_mutex_t             mutex;
  shopify_log_script_t       *script;
  time_t                      error_log_time;
  shopify_log_fmt_t          *format;
  uint64_t                    head;
  uint64_t                    tail;
  shopify_log_msg_t           slots[LOG_BUFFER_SLOTS];
} shopify_log_t;


typedef struct {
  ngx_array_t                *logs;       /* array of shopify_log_t */
  ngx_uint_t                  off;        /* unsigned  off:1 */
} shopify_log_loc_conf_t;


typedef struct {
  ngx_str_t                   name;
  size_t                      len;
  shopify_log_op_run_pt       run;
} shopify_log_var_t;


static void shopify_log_write(ngx_http_request_t *r, shopify_log_t *log, u_char *buf, size_t len);
static u_char *shopify_log_pipe(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_time(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_iso8601(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_msec(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_request_time(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_status(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_bytes_sent(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static u_char *shopify_log_request_length(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);

static ngx_int_t shopify_log_variable_compile(ngx_conf_t *cf, shopify_log_op_t *op, ngx_str_t *value);
static size_t shopify_log_variable_getlen(ngx_http_request_t *r, uintptr_t data);
static u_char *shopify_log_variable(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op);
static uintptr_t shopify_log_escape(u_char *dst, u_char *src, size_t size);

static char *shopify_log_open_msq(ngx_conf_t *cf, int *msqid);

static void *shopify_log_create_main_conf(ngx_conf_t *cf);
static void *shopify_log_create_loc_conf(ngx_conf_t *cf);
static char *shopify_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *shopify_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *shopify_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *shopify_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static ngx_int_t shopify_log_init(ngx_conf_t *cf);

static ngx_command_t  shopify_log_commands[] = {
  { ngx_string("shopify_log_format"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    shopify_log_set_format,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("shopify_access_log"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
      |NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
    shopify_log_set_log,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  ngx_null_command
};


static ngx_http_module_t  shopify_log_module_ctx = {
  NULL,                                  /* preconfiguration */
  shopify_log_init,                     /* postconfiguration */

  shopify_log_create_main_conf,         /* create main configuration */
  NULL,                                  /* init main configuration */

  NULL,                                  /* create server configuration */
  NULL,                                  /* merge server configuration */

  shopify_log_create_loc_conf,          /* create location configuration */
  shopify_log_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  shopify_log_module = {
  NGX_MODULE_V1,
  &shopify_log_module_ctx,              /* module context */
  shopify_log_commands,                 /* module directives */
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

static shopify_log_var_t  shopify_log_vars[] = {
  { ngx_string("pipe"), 1, shopify_log_pipe },
  { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
    shopify_log_time },
  { ngx_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
    shopify_log_iso8601 },
  { ngx_string("msec"), NGX_TIME_T_LEN + 4, shopify_log_msec },
  { ngx_string("request_time"), NGX_TIME_T_LEN + 4,
    shopify_log_request_time },
  { ngx_string("status"), NGX_INT_T_LEN, shopify_log_status },
  { ngx_string("bytes_sent"), NGX_OFF_T_LEN, shopify_log_bytes_sent },
  { ngx_string("body_bytes_sent"), NGX_OFF_T_LEN,
    shopify_log_body_bytes_sent },
  { ngx_string("request_length"), NGX_SIZE_T_LEN,
    shopify_log_request_length },

  { ngx_null_string, 0, NULL }
};

static ngx_int_t
shopify_log_handler(ngx_http_request_t *r)
{
  u_char                   *line, *p;
  size_t                    len;
  ngx_uint_t                i, l;
  shopify_log_t            *log;
  shopify_log_op_t         *op;
  shopify_log_loc_conf_t   *lcf;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http log handler");

  lcf = ngx_http_get_module_loc_conf(r, shopify_log_module);

  if (lcf->off) {
    return NGX_OK;
  }

  log = lcf->logs->elts;
  for (l = 0; l < lcf->logs->nelts; l++) {

    len = 0;
    op = log[l].format->ops->elts;
    for (i = 0; i < log[l].format->ops->nelts; i++) {
      if (op[i].len == 0) {
        len += op[i].getlen(r, op[i].data);

      } else {
        len += op[i].len;
      }
    }

    len += NGX_LINEFEED_SIZE;

    line = ngx_pnalloc(r->pool, len);
    if (line == NULL) {
      return NGX_ERROR;
    }

    p = line;

    for (i = 0; i < log[l].format->ops->nelts; i++) {
      p = op[i].run(r, p, &op[i]);
    }

    ngx_linefeed(p);

    shopify_log_write(r, &log[l], line, p - line);
  }

  return NGX_OK;
}

static void
shopify_log_write(ngx_http_request_t *r, shopify_log_t *log, u_char *buf, size_t len)
{
  int                  ret;
  time_t               now;
  shopify_log_msg_t   *msg;
  shopify_log_msg_t    lmsg;

  // This line has a race condition. That's fine though, it's just a fast-path shortcut.
  if (log->head == log->tail) {
    // fast path. If there's no data in the buffer, we don't need to lock anything; just allocate a
    // message on the stack and msgsnd() that.
    lmsg.mtype = SVMQ_MESSAGE_TYPE;
    strncpy(lmsg.mtext, (char*)buf, len);
    lmsg.mtext[len] = 0;
    ret = msgsnd(log->msqid, &lmsg, sizeof(shopify_log_msg_t), IPC_NOWAIT);
    // If the message couldn't be delivered, we have to insert it into the ring buffer to be delivered next time.
    if (ret >= 0) {
      // nothing
    } else if (errno == EAGAIN) { // consumer isn't keeping up with the queue. put message in ring buffer.
      shopify_log_msg_t *msg;
      // grab the mutex and put it in the ring buffer
      pthread_mutex_lock(&log->mutex);
      msg = &log->slots[log->head++ % LOG_BUFFER_SLOTS];
      msg->mtype = SVMQ_MESSAGE_TYPE;
      strncpy(msg->mtext, (char*)buf, len);
      msg->mtext[len] = 0;
      pthread_mutex_unlock(&log->mutex);
    } else { // An actual error, which should be logged.
      now = ngx_time();
      if (now - log->error_log_time >= LOG_ERROR_TIMEOUT) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, errno, "msgsnd(3) failed in shopify_log_module");
        log->error_log_time = now;
      }
    }
    return;
  }

  // Slow path. We are in a situation where there is (probably) data in the ring buffer
  // which we must attempt to deliver before our current message.
  pthread_mutex_lock(&log->mutex);

  if (log->head - log->tail >= LOG_BUFFER_SLOTS) {
    now = ngx_time();
    if (now - log->error_log_time >= LOG_ERROR_TIMEOUT) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, errno,
          "log production rate in shopify_log_module is exceeding queue consumer throughput; log messages are being discarded");
      log->error_log_time = now;
    }
  }

  msg = &log->slots[log->head++ % LOG_BUFFER_SLOTS];
  msg->mtype = SVMQ_MESSAGE_TYPE;
  strncpy(msg->mtext, (char*)buf, len);
  msg->mtext[len] = 0;

  while (log->tail != log->head) { // fail means we're caught up; no messages to send.

    msg = &log->slots[log->tail % LOG_BUFFER_SLOTS];
    ret = msgsnd(log->msqid, msg, sizeof(shopify_log_msg_t), IPC_NOWAIT);

    if (ret >= 0) { // success! "remove" the item from the queue and send another.
      log->tail++;
    } else if (errno == EAGAIN) { // Consumer isn't ready for another item yet. We'll just try again on the next log line.
      break;
    } else { // An error happened that we should log.
      now = ngx_time();
      if (now - log->error_log_time >= 60) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, errno, "msgsnd(3) failed in shopify_log_module");
        log->error_log_time = now;
      }
    }
  }
  pthread_mutex_unlock(&log->mutex);
}

static u_char *
shopify_log_copy_short(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  size_t     len;
  uintptr_t  data;

  len = op->len;
  data = op->data;

  while (len--) {
    *buf++ = (u_char) (data & 0xff);
    data >>= 8;
  }

  return buf;
}

static u_char *
shopify_log_copy_long(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
shopify_log_pipe(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  if (r->pipeline) {
    *buf = 'p';
  } else {
    *buf = '.';
  }

  return buf + 1;
}


static u_char *
shopify_log_time(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  return ngx_cpymem(buf, ngx_cached_http_log_time.data,
      ngx_cached_http_log_time.len);
}

static u_char *
shopify_log_iso8601(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  return ngx_cpymem(buf, ngx_cached_http_log_iso8601.data,
      ngx_cached_http_log_iso8601.len);
}

static u_char *
shopify_log_msec(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  ngx_time_t  *tp;

  tp = ngx_timeofday();

  return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


static u_char *
shopify_log_request_time(ngx_http_request_t *r, u_char *buf,
    shopify_log_op_t *op)
{
  ngx_time_t      *tp;
  ngx_msec_int_t   ms;

  tp = ngx_timeofday();

  ms = (ngx_msec_int_t)
    ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
  ms = ngx_max(ms, 0);

  return ngx_sprintf(buf, "%T.%03M", ms / 1000, ms % 1000);
}


static u_char *
shopify_log_status(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  ngx_uint_t  status;

  if (r->err_status) {
    status = r->err_status;

  } else if (r->headers_out.status) {
    status = r->headers_out.status;

  } else if (r->http_version == NGX_HTTP_VERSION_9) {
    status = 9;

  } else {
    status = 0;
  }

  return ngx_sprintf(buf, "%03ui", status);
}


static u_char *
shopify_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
    shopify_log_op_t *op)
{
  return ngx_sprintf(buf, "%O", r->connection->sent);
}


/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */

static u_char *
shopify_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf,
    shopify_log_op_t *op)
{
  off_t  length;

  length = r->connection->sent - r->header_size;

  if (length > 0) {
    return ngx_sprintf(buf, "%O", length);
  }

  *buf = '0';

  return buf + 1;
}


static u_char *
shopify_log_request_length(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  return ngx_sprintf(buf, "%O", r->request_length);
}


static ngx_int_t
shopify_log_variable_compile(ngx_conf_t *cf, shopify_log_op_t *op, ngx_str_t *value)
{
  ngx_int_t  index;

  index = ngx_http_get_variable_index(cf, value);
  if (index == NGX_ERROR) {
    return NGX_ERROR;
  }

  op->len = 0;
  op->getlen = shopify_log_variable_getlen;
  op->run = shopify_log_variable;
  op->data = index;

  return NGX_OK;
}


static size_t
shopify_log_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
  uintptr_t                   len;
  ngx_http_variable_value_t  *value;

  value = ngx_http_get_indexed_variable(r, data);

  if (value == NULL || value->not_found) {
    return 1;
  }

  len = shopify_log_escape(NULL, value->data, value->len);

  value->escape = len ? 1 : 0;

  return value->len + len * 3;
}


static u_char *
shopify_log_variable(ngx_http_request_t *r, u_char *buf, shopify_log_op_t *op)
{
  ngx_http_variable_value_t  *value;

  value = ngx_http_get_indexed_variable(r, op->data);

  if (value == NULL || value->not_found) {
    *buf = '-';
    return buf + 1;
  }

  if (value->escape == 0) {
    return ngx_cpymem(buf, value->data, value->len);

  } else {
    return (u_char *) shopify_log_escape(buf, value->data, value->len);
  }
}


static uintptr_t
shopify_log_escape(u_char *dst, u_char *src, size_t size)
{
  ngx_uint_t      n;
  static u_char   hex[] = "0123456789ABCDEF";

  static uint32_t   escape[] = {
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    /*             ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

    /*             _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
    0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

    /*              ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
  };

  if (dst == NULL) {

    /* find the number of the characters to be escaped */

    n = 0;

    while (size) {
      if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
        n++;
      }
      src++;
      size--;
    }

    return (uintptr_t) n;
  }

  while (size) {
    if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
      *dst++ = '\\';
      *dst++ = 'x';
      *dst++ = hex[*src >> 4];
      *dst++ = hex[*src & 0xf];
      src++;

    } else {
      *dst++ = *src++;
    }
    size--;
  }

  return (uintptr_t) dst;
}


static void *
shopify_log_create_main_conf(ngx_conf_t *cf)
{
  shopify_log_main_conf_t  *conf;

  shopify_log_fmt_t  *fmt;

  conf = ngx_pcalloc(cf->pool, sizeof(shopify_log_main_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(shopify_log_fmt_t))
      != NGX_OK)
  {
    return NULL;
  }

  fmt = ngx_array_push(&conf->formats);
  if (fmt == NULL) {
    return NULL;
  }

  ngx_str_set(&fmt->name, "combined");

  fmt->ops = ngx_array_create(cf->pool, 16, sizeof(shopify_log_op_t));
  if (fmt->ops == NULL) {
    return NULL;
  }

  return conf;
}

static char *
shopify_log_open_msq(ngx_conf_t *cf, int *msqid)
{
  *msqid = msgget(MESSAGE_QUEUE_KEY, 0660 | IPC_CREAT);
  if (msqid < 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "msgget failed with errno=%d", errno);
    return NGX_CONF_ERROR;
  }
  return NGX_OK;
}


static void *
shopify_log_create_loc_conf(ngx_conf_t *cf)
{
  shopify_log_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(shopify_log_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  return conf;
}


static char *
shopify_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  shopify_log_loc_conf_t *prev = parent;
  shopify_log_loc_conf_t *conf = child;

  shopify_log_t            *log;
  shopify_log_fmt_t        *fmt;
  shopify_log_main_conf_t  *lmcf;

  if (conf->logs || conf->off) {
    return NGX_CONF_OK;
  }

  conf->logs = prev->logs;
  conf->off = prev->off;

  if (conf->logs || conf->off) {
    return NGX_CONF_OK;
  }

  conf->logs = ngx_array_create(cf->pool, 2, sizeof(shopify_log_t));
  if (conf->logs == NULL) {
    return NGX_CONF_ERROR;
  }

  log = ngx_array_push(conf->logs);
  if (log == NULL) {
    return NGX_CONF_ERROR;
  }

  log->msqid = -1;
  pthread_mutex_init(&log->mutex, NULL);
  log->script = NULL;
  log->error_log_time = 0;

  lmcf = ngx_http_conf_get_module_main_conf(cf, shopify_log_module);
  fmt = lmcf->formats.elts;

  /* the default "combined" format */
  log->format = &fmt[0];

  return NGX_CONF_OK;
}


static char *
shopify_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  shopify_log_loc_conf_t *llcf = conf;

  ngx_uint_t                  i, n;
  ngx_str_t                  *value, name, s;
  shopify_log_t             *log;
  shopify_log_fmt_t         *fmt;
  shopify_log_main_conf_t   *lmcf;
  ngx_http_script_compile_t   sc;

  value = cf->args->elts;

  if (ngx_strcmp(value[1].data, "off") == 0) {
    llcf->off = 1;
    if (cf->args->nelts == 2) {
      return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "invalid parameter \"%V\"", &value[2]);
    return NGX_CONF_ERROR;
  }

  if (cf->args->nelts != 2 || ngx_strcmp(value[1].data, "on") != 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "shopify_access_log requires one parameter, which must be either \"off\" or \"on\"");
    return NGX_CONF_ERROR;
  }

  if (llcf->logs == NULL) {
    llcf->logs = ngx_array_create(cf->pool, 2, sizeof(shopify_log_t));
    if (llcf->logs == NULL) {
      return NGX_CONF_ERROR;
    }
  }

  lmcf = ngx_http_conf_get_module_main_conf(cf, shopify_log_module);

  log = ngx_array_push(llcf->logs);
  if (log == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_memzero(log, sizeof(shopify_log_t));
  pthread_mutex_init(&log->mutex, NULL);

  if (shopify_log_open_msq(cf, &log->msqid) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  ngx_str_set(&name, "shopify_default");

  fmt = lmcf->formats.elts;
  for (i = 0; i < lmcf->formats.nelts; i++) {
    if (fmt[i].name.len == name.len
        && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
    {
      log->format = &fmt[i];
      break;
    }
  }

  if (log->format == NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
shopify_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  shopify_log_main_conf_t *lmcf = conf;

  ngx_str_t           *value;
  ngx_uint_t           i;
  shopify_log_fmt_t  *fmt;

  if (cf->cmd_type != NGX_HTTP_MAIN_CONF) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "the \"log_format\" directive may be used "
        "only on \"http\" level");
  }

  value = cf->args->elts;

  fmt = lmcf->formats.elts;
  for (i = 0; i < lmcf->formats.nelts; i++) {
    if (fmt[i].name.len == value[1].len
        && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
    {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
          "duplicate \"log_format\" name \"%V\"",
          &value[1]);
      return NGX_CONF_ERROR;
    }
  }

  fmt = ngx_array_push(&lmcf->formats);
  if (fmt == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_str_set(&fmt->name, "shopify_default");

  fmt->ops = ngx_array_create(cf->pool, 16, sizeof(shopify_log_op_t));
  if (fmt->ops == NULL) {
    return NGX_CONF_ERROR;
  }

  return shopify_log_compile_format(cf, fmt->ops, cf->args, 1);
}

#define PUSH_CHAR(chr) \
  if (shopify_log_push_char(ops, chr) == NGX_CONF_ERROR) return NGX_CONF_ERROR;

static inline char *
shopify_log_push_char(ngx_array_t *ops, char chr)
{
  shopify_log_op_t *op = ngx_array_push(ops);
  if (op == NULL) {
    return NGX_CONF_ERROR;
  }
  op->len = 1;
  op->getlen = NULL;
  op->run = shopify_log_copy_short;
  op->data = chr;
  return 0;
}

static u_char *json_header = (u_char *) "{\"event_source\":\"nginx\",";

static char *
shopify_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
  u_char              *data, *p, ch;
  size_t               i, len;
  ngx_str_t           *value, var;
  shopify_log_op_t   *op;
  shopify_log_var_t  *v;
  int                 key0value1;
  int                 initial;

  value = args->elts;

  op = ngx_array_push(ops);
  if (op == NULL) {
    return NGX_CONF_ERROR;
  }
  op->len = 24;
  op->getlen = NULL;
  op->run = shopify_log_copy_long;
  op->data = (uintptr_t) json_header;

  key0value1 = 0; // read a key first
  initial = 1;

  for ( /* void */ ; s < args->nelts; s++) {

    i = 0;

    if (initial) {
      initial = 0;
      key0value1 = 1;
    } else if (key0value1) { // about to read a value
      PUSH_CHAR(':');
      key0value1 = 0;
    } else { // about to read a key
      PUSH_CHAR(',');
      key0value1 = 1;
    }

    while (i < value[s].len) {

      data = &value[s].data[i];

      if (value[s].data[i] == '$') {

        if (++i == value[s].len) {
          goto invalid;
        }

        var.data = &value[s].data[i];

        for (var.len = 0; i < value[s].len; i++, var.len++) {
          ch = value[s].data[i];

          if ((ch >= 'A' && ch <= 'Z')
              || (ch >= 'a' && ch <= 'z')
              || (ch >= '0' && ch <= '9')
              || ch == '_')
          {
            continue;
          }

          break;
        }

        if (var.len == 0) {
          goto invalid;
        }

        PUSH_CHAR('"');
        op = ngx_array_push(ops);
        if (op == NULL) {
          return NGX_CONF_ERROR;
        }
        PUSH_CHAR('"');

        for (v = shopify_log_vars; v->name.len; v++) {

          if (v->name.len == var.len
              && ngx_strncmp(v->name.data, var.data, var.len) == 0)
          {
            op->len = v->len;
            op->getlen = NULL;
            op->run = v->run;
            op->data = 0;

            goto found;
          }
        }

        if (shopify_log_variable_compile(cf, op, &var) != NGX_OK) {
          return NGX_CONF_ERROR;
        }

found:

        continue;
      }

      i++;

      while (i < value[s].len && value[s].data[i] != '$') {
        i++;
      }

      len = &value[s].data[i] - data;

      if (len) {

        PUSH_CHAR('"');
        op = ngx_array_push(ops);
        if (op == NULL) {
          return NGX_CONF_ERROR;
        }
        PUSH_CHAR('"');

        op->len = len;
        op->getlen = NULL;

        if (len <= sizeof(uintptr_t)) {
          op->run = shopify_log_copy_short;
          op->data = 0;

          while (len--) {
            op->data <<= 8;
            op->data |= data[len];
          }

        } else {
          op->run = shopify_log_copy_long;

          p = ngx_pnalloc(cf->pool, len);
          if (p == NULL) {
            return NGX_CONF_ERROR;
          }

          ngx_memcpy(p, data, len);
          op->data = (uintptr_t) p;
        }
      }
    }
  }

  PUSH_CHAR('}');

  return NGX_CONF_OK;

invalid:

  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

  return NGX_CONF_ERROR;
}

static ngx_int_t
shopify_log_init(ngx_conf_t *cf)
{
  ngx_str_t                  *value;
  ngx_array_t                 a;
  ngx_http_handler_pt        *h;
  shopify_log_fmt_t          *fmt;
  ngx_http_core_main_conf_t  *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = shopify_log_handler;

  return NGX_OK;
}
