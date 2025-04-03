CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

TARGET = traffic_monitor

all: $(TARGET).o

$(TARGET).o: $(TARGET).c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c $(TARGET).c
	$(LLVM_STRIP) -g $(TARGET).o

clean:
	rm -f $(TARGET).o 