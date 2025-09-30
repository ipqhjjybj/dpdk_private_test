CC = gcc

TOPDIR=/data/f-stack

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

# mbedTLS库路径配置
MBEDTLS_INCLUDE ?= /usr/local/include
MBEDTLS_LIB ?= /usr/local/lib


PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -I$(MBEDTLS_INCLUDE)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma
LIBS+= -L$(MBEDTLS_LIB) -lmbedtls -lmbedx509 -lmbedcrypto

TARGET="fstack_tcp_client"
all:
	cc ${CFLAGS} -DINET6 -o ${TARGET} fstack_tcp_client.c ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET} ${TARGET}_epoll
