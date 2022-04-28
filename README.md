# singlestore-auth-helper - helper utility for browser-based authentication

[![GoDoc](https://godoc.org/github.com/singlestore/singlestore-auth-helper?status.svg)](https://pkg.go.dev/github.com/singlestore/singlestore-auth-helper)

Install:

	go install github.com/memsql/singlestore-auth-helper@latest

---

The singlestore-auth-helper is a small utility that opens a browser to a well-known
URL with some parameters. It also puts up a http server to receive an eventual response
from the browser.

The idea is that the browser session will be used to capture a JWT. The JWT is the
output so that the caller of the singlestore-auth-helper can use it for database access.

```sh
mysql -u $EMAIL_ADDRESS -h $CLUSTER_HOSTNAME -P $CLUSTER_PORT --password=`singlestore-auth-helper` --ssl=TRUE
```
