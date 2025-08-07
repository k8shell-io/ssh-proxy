module github.com/k8shell-io/ssh-proxy

go 1.24.5

require (
	github.com/k8shell-io/identity v0.11.2
	github.com/k8shell-io/yaml-config v0.1.1
	github.com/rs/zerolog v1.34.0
	golang.org/x/crypto v0.40.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/sys v0.34.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// forked version of golang.org/x/crypto with allowed_auths_callback patch
replace golang.org/x/crypto v0.40.0 => github.com/k8shell-io/crypto v0.40.1-ssh-proxy
