build:
	GOOS=linux go build ./cmd/envoy-runner
	mv envoy-runner bin/
