# shopify_log_module for nginx

This is a module for nginx that writes the access log to a SysV Message Queue
rather than to a file, and also logs in JSON. It mostly consists of the default
nginx log module, with a few additions and deletions:

* Removed support for multiple log formats.
* Removed support for multiple log outputs.
* Rewrote log formatting to log in JSON.
* Rather than writing to files, log to a SysV MQ.

## Status

Not quite ready yet. Needs more testing.

## Installation

You can compile it by cd'ing into a new nginx source unpack and running:

    auto/configure --add-module=/path/to/shopify_log_module
    make
    make install
    # or just run
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

Takes two parameters, which are parameters to `ftok(3)`, used to locate a SysV
MQ. The first is a file, which must exist, and the user running nginx must have
access to. The second is a single character which represents an ID. A single
file can be used for multiple MQs by varying the ID. Example:

```
shopify_access_log /usr/local/nginx/access.svmq b;
```

`shopify_access_log` should come after `shopify_log_format`. To suppress the
default file-logging, you can specify `access_log off;`.

