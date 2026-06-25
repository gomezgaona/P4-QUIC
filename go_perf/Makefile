BIN := ..

# CGO_ENABLED=0 -> fully static binaries with no glibc dependency, so the
# server runs on PC2 even though it has an older glibc than the build host.
export CGO_ENABLED := 0

.PHONY: all clean

all: $(BIN)/quic_perf_go_server $(BIN)/quic_perf_go_client

$(BIN)/quic_perf_go_server: server/main.go go.mod
	go build -o $@ ./server

$(BIN)/quic_perf_go_client: client/main.go go.mod
	go build -o $@ ./client

clean:
	rm -f $(BIN)/quic_perf_go_server $(BIN)/quic_perf_go_client
