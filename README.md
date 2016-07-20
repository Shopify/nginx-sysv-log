**This module is not actively maintained and can be removed without notice. Using it in production is strongly discouraged.**

# shopify_log_module for nginx

This is a module for nginx that writes the access log to a SysV Message Queue
rather than to a file, and also logs in JSON. It mostly consists of the default
nginx log module, with a few additions and deletions:

* Removed support for multiple log formats.
* Removed support for multiple log outputs.
* Rewrote log formatting to log in JSON.
* Rather than writing to files, log to a SysV MQ.

## Installation

You can compile it by cd'ing into a new nginx source unpack and running:

    auto/configure --add-module=/path/to/shopify_log_module
    make
    make install
    # or instead of make install, just run:
    objs/nginx

This does not override the existing log facility; it provides its own:

### `shopify_log_format`

The syntax for this function is simply a list of alternating JSON keys/values.
For example:

```
shopify_log_format  event_timestamp    $time_iso8601
                    event_id           $upstream_http_x_request_id
                    event_dvc          asdfasdfasdf
                    status             $status
                    scheme             $scheme
                    app_name           $upstream_http_x_app_name
                    ;
```

### `shopify_access_log`

Takes one parameter, either "on" or "off". If enabled, the queue used is always
`0xDEADC0DE`.

```
shopify_access_log on;
```

`shopify_access_log` should come after `shopify_log_format`. To suppress the
default file-logging, you can specify `access_log off;`.

