# singlestore-auth-helper - helper utility for browser-based authentication

[![GoDoc](https://godoc.org/github.com/singlestore/singlestore-auth-helper?status.svg)](https://pkg.go.dev/github.com/singlestore/singlestore-auth-helper)

Install:

	go install github.com/memsql/singlestore-auth-helper@latest

To override the location:

	env GOBIN=/some/bin go install github.com/memsql/singlestore-auth-helper@latest

---

The singlestore-auth-helper is a small utility that opens a browser to a well-known
URL with some parameters. It also puts up a http server to receive an eventual response
from the browser.

The idea is that the browser session will be used to capture a JWT. The JWT is the
output so that the caller of the singlestore-auth-helper can use it for database access.

With a mysql client:

```sh
mysql -h $CLUSTER_HOSTNAME -P $CLUSTER_PORT -u '' --password=`singlestore-auth-helper` --ssl=TRUE
```

With a singlestore client:

```sh
singlestore -h $CLUSTER_HOSTNAME -P $CLUSTER_PORT -u '' --password=`singlestore-auth-helper` --ssl=TRUE --enable-cleartext-plugin
```

Note: the Safari browser is not compatible with the `singlestore-auth-helper` because it lacks a cross-site-scripting exception for localhost.

To set the results of the auth-helper in environment variables for use in scripting, use the `env-name` and `env-status` command line options. When these are used, the status and token are prefixed with the given name, such as:

```sh
singlestore-auth-helper --env-status=STATUS --env-name=TOKEN

STATUS=0
TOKEN=eyJhbGcibW9zc0BzaW5nbGVzdG9yZS5jb20iLCJhdWQiOlsiZW5naW5lIiwiIXBvcnRhbCJdLCJleHAiOjE
```

The output can be evaluated, thus setting the environment variables:

```shell
eval $(singlestore-auth-helper --env-status=STATUS --env-name=TOKEN)

echo $TOKEN
eyJhbGcibW9zc0BzaW5nbGVzdG9yZS5jb20iLCJhdWQiOlsiZW5naW5lIiwiIXBvcnRhbCJdLCJleHAiOjE
```
