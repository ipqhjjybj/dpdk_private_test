CC = gcc
CFLAGS = -Wall -O2 -I/opt/fstack/include -I/opt/fstack/dpdk/include
LDFLAGS = -L/opt/fstack/lib -L/opt/fstack/dpdk/lib
LDLIBS = -lfs -ldpdk -lnuma -lpthread -ldl

TARGET = fstack_tcp_client
SRCS = fstack_tcp_client.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)