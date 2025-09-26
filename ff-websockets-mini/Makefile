# 替换为实际路径
FSTACK_DIR := /path/to/fstack
DPDK_DIR := $(FSTACK_DIR)/dpdk
MBEDTLS_DIR := /path/to/mbedtls
LWS_DIR := /path/to/libwebsockets  # 如需扩展可添加，当前示例未用到

# 编译器和 flags
CC := gcc
CFLAGS := -Wall -O2 -Wno-unused-function \
          -I$(FSTACK_DIR)/include \
          -I$(DPDK_DIR)/include \
          -I$(MBEDTLS_DIR)/include \
          -include $(FSTACK_DIR)/include/ff_config.h

LDFLAGS := -L$(FSTACK_DIR)/lib \
           -L$(DPDK_DIR)/lib \
           -L$(MBEDTLS_DIR)/lib

# 链接库
LDLIBS := -lfs -ldpdk -lmbedtls -lmbedx509 -lmbedcrypto \
          -lnuma -lpthread -ldl -lrt

# 目标文件和可执行文件
TARGET := fstack_binance_client
SRCS := fstack_binance_client.c

# 默认目标
all: $(TARGET)

# 编译规则
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

# 清理
clean:
	rm -f $(TARGET) *.o

# 安装（可选）
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
    