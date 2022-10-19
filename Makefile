GIT=$(shell git describe --tags)
DATE=$(shell date +%Y%m%d)

all:
	go build -ldflags "-X main.BuildGitVersion=${GIT} -X main.BuildTime=${DATE}" -buildmode=c-shared -o vkcloudlogs-fluent-bit.so .

clean:
	rm -rf *.so *.h *~

tests-unit-run:
	go test -race -v ./vkcloudlogs/...
	go test -race -v ./*.go
