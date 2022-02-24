# make formats, tests, and validates


DOLLAR=$

all:
	git status | awk '/modified:/{print ${DOLLAR}NF}' | perl -n -e 'print if /\.go${DOLLAR}/' | xargs -r gofmt -w -s
	go mod tidy
	go test ./...
	golangci-lint run
	@ echo any output from the following command indicates an out-of-date direct dependency
	go list -u -m -f '{{if (and (not .Indirect) .Update)}}{{.}}{{end}}' all
