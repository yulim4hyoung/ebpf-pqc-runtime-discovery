# Runtime PQC Discovery - Build

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD := $(ROOT)/build
LIBBPF := $(ROOT)/third_party/libbpf/src
# bpftool from the distro package (linux-tools-common / linux-tools-$(uname -r)).
# Override with `make BPFTOOL=/path/to/bpftool vmlinux` if it is not on PATH.
BPFTOOL ?= bpftool

CLANG ?= clang
LLC ?= llc
CC ?= gcc

LIBBPF_UAPI := $(ROOT)/third_party/libbpf/include/uapi
LIBBPF_INC := $(ROOT)/third_party/libbpf/include
INCLUDES := -I$(ROOT)/include -I$(ROOT)/include/bpf -I$(LIBBPF_INC) -I$(LIBBPF) -I$(LIBBPF_UAPI)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I$(ROOT)/include/bpf -I$(ROOT)/include \
	-I$(LIBBPF) $(INCLUDES)

.PHONY: all clean bpf userspace libbpf

all: bpf userspace

$(BUILD):
	mkdir -p $(BUILD)

bpf: $(BUILD)/crypto_monitor.bpf.o

$(BUILD)/crypto_monitor.bpf.o: src/bpf/crypto_monitor.bpf.c include/events.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Static libbpf built from the vendored source (needs libelf-dev and zlib1g-dev).
libbpf: $(LIBBPF)/libbpf.a

$(LIBBPF)/libbpf.a:
	$(MAKE) -C $(LIBBPF) BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1

userspace: $(BUILD)/crypto-monitor

$(BUILD)/crypto-monitor: src/userspace/crypto_monitor.c include/events.h \
		$(LIBBPF)/libbpf.a | $(BUILD)
	$(CC) -Wall -Wextra -g -O2 $(INCLUDES) \
		$< -o $@ $(LIBBPF)/libbpf.a /usr/lib/x86_64-linux-gnu/libelf.so.1 -lz

clean:
	rm -rf $(BUILD)

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/bpf/vmlinux.h
