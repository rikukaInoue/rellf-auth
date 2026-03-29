.PHONY: build build-api build-presignup clean zip tidy fmt vet swagger dev dev-local floci-up floci-setup

build: build-api build-presignup

build-api:
	GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o dist/api/bootstrap cmd/lambda/main.go

build-presignup:
	GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o dist/presignup/bootstrap cmd/trigger/presignup/main.go

clean:
	rm -rf dist/

zip: build
	cd dist/api && zip -j ../../function.zip bootstrap
	cd dist/presignup && zip -j ../../presignup.zip bootstrap

tidy:
	go mod tidy

fmt:
	go fmt ./...

vet:
	go vet ./...

swagger:
	swag init -g cmd/lambda/main.go -o docs --parseDependency --parseInternal

dev:
	set -a && . ./.env && set +a && go run cmd/server/main.go

dev-local:
	set -a && . ./.env.local && set +a && go run cmd/server/main.go

floci-up:
	docker compose up -d

floci-setup: floci-up
	@echo "Waiting for floci to be ready..."
	@sleep 3
	bash scripts/setup-local.sh
