.PHONY: build test vet guard cross clean

build:
	go build -o bin/vault ./cmd/vault

test:
	go test ./...

vet:
	go vet ./...

# Prove the dependency graph pulls in zero CGo.
guard:
	CC=/bin/false CGO_ENABLED=0 go build ./... && echo "no-cgo build OK"

# Cross-compile all six targets, CGO_ENABLED=0.
cross:
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; [ "$$os" = windows ] && ext=.exe; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -o bin/vault-$$os-$$arch$$ext ./cmd/vault \
			&& echo "  $$t OK"; \
	done

clean:
	rm -rf bin
