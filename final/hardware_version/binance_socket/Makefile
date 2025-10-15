CC = gcc

TOPDIR=/data/f-stack

ifeq ($(FF_PATH),)
	FF_PATH=${TOPDIR}
endif


# mbedTLS库路径配置
MBEDTLS_INCLUDE ?= /usr/local/include
MBEDTLS_LIB ?= /usr/local/lib



CFLAGS += -I$(MBEDTLS_INCLUDE)

LIBS+= -L$(MBEDTLS_LIB) -lmbedtls -lmbedx509 -lmbedcrypto

TARGET="binance_ws_client"
all:
	cc ${CFLAGS} -o ${TARGET} binance_ws_client.c ${LIBS}

.PHONY: clean
clean:
	rm -f *.o ${TARGET} 