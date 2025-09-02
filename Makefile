# Variables
GOOS_LIST := linux 
GOARCH_LIST := amd64 arm64
REPO=fitcr.ksi.in.fit.cvut.cz

# Default target
all: build

# Initialize Go module
init:
	@echo "Initializing Go module..."
	go mod tidy

image:
	@echo "SSH Proxy docker image"
	@rm -fr docker/ssh-proxy/files
	@mkdir -p docker/ssh-proxy/files
	@echo "Downloading vendor modules..."
	@go mod vendor -o docker/ssh-proxy/files/vendor
	@echo "Building image..."
	@version=$$(git describe --tags --match '*' | sed 's/-g.*//') && \
	cp -r go.mod go.sum internal main.go docker/ssh-proxy/files && \
	cd docker/ssh-proxy && docker build --build-arg VERSION=$$version \
		--build-arg COMMIT_ID=$$(git rev-parse --short HEAD) -t $(REPO)/$$(cat ./BUILD):$$version .

