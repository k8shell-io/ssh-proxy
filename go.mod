module github.com/k8shell-io/ssh-proxy

go 1.24.5

require (
	github.com/k8shell-io/common v0.11.22
	github.com/k8shell-io/identity v0.11.10
	github.com/k8shell-io/k8shelld v0.11.2
	github.com/k8shell-io/provisioner v0.11.19
	github.com/rs/zerolog v1.34.0
	golang.org/x/crypto v0.40.0
	google.golang.org/grpc v1.74.2
)

require (
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.27.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// forked version of golang.org/x/crypto with allowed_auths_callback patch
replace golang.org/x/crypto v0.40.0 => github.com/k8shell-io/crypto v0.41.1-ssh-proxy
