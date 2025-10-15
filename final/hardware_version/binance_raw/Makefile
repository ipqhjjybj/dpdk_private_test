FF_PATH="/data/f-stack"

# mbedTLS库路径配置
MBEDTLS_INCLUDE ?= /usr/local/include
MBEDTLS_LIB ?= /usr/local/lib

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "No installation of DPDK found, maybe you should export environment variable `PKG_CONFIG_PATH`")
endif

PKGCONF ?= pkg-config

CFLAGS += -O0 -g -gdwarf-2 $(shell $(PKGCONF) --cflags libdpdk) -I$(MBEDTLS_INCLUDE)

LIBS+= $(shell $(PKGCONF) --static --libs libdpdk)
LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma
LIBS+= -L$(MBEDTLS_LIB) -lmbedtls -lmbedx509 -lmbedcrypto

TARGET="binance_ws_client"
all:

	cc ${CFLAGS} -o ${TARGET} binance_ws_client.c ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET} 