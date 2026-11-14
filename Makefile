# Build: templ -> Tailwind CSS (scans .templ/.go) -> static Go binary
export PATH := $(PATH):/usr/local/go/bin:$(HOME)/go/bin
BIN := bin/vpnaas-ui

.PHONY: all generate css test build clean
all: build

generate:
	templ generate

css: generate
	tailwindcss -i internal/web/static/input.css -o internal/web/static/app.css --minify

test: css
	go vet ./...
	go test ./...

build: test
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o $(BIN) ./cmd/vpnaas-ui

clean:
	rm -rf bin internal/views/*_templ.go internal/web/static/app.css
