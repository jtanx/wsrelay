.PHONY: build version

build: version common/gen_defs.go
	rm -f *.exe*
	rm -f *.log
	go build -ldflags="-s -w" ./cmd/client
	go build -ldflags="-s -w" ./cmd/receiver
	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -ldflags="-s -w" -tags "osusergo" ./cmd/receiver
	go build -ldflags="-s -w" ./cmd/server

version:
	@echo -e "package common\n\nconst GitRev = \"$$(git rev-parse HEAD)\"\n" > common/gen_version.go

common/gen_defs.go: common/gendef/gendef.go
	go generate ./common/defs.go
