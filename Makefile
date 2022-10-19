GIT=$(shell git describe --tags)
DATE=$(shell date +%Y%m%d)
CURR_DIR=$(shell pwd)

generate-grpc:
	docker run \
		--user $(shell id -u):$(shell id -g) \
		-v ${CURR_DIR}:/defs namely/protoc-all:1.42_1 \
		--with-validator \
		-l go \
		-o gen \
		-f spec/api.proto

all:
	go build -ldflags "-X main.BuildGitVersion=${GIT} -X main.BuildTime=${DATE}" -buildmode=c-shared -o vkcloudlogs-fluent-bit.so .

clean:
	rm -rf *.so *.h *~

tests-unit-run:
	go test -race -v ./vkcloudlogs/...
	go test -race -v ./*.go
