# F-Stack + mbedTLS 币安WebSocket客户端 Makefile
# 极简版本，适用于DPDK环境

# =============================================================================
# 配置部分 - 请根据实际安装路径修改
# =============================================================================

# F-Stack安装路径
FSTACK_DIR ?= /usr/local/fstack

# DPDK安装路径（通常F-Stack会包含DPDK）
DPDK_DIR ?= $(FSTACK_DIR)/dpdk

# mbedTLS安装路径
MBEDTLS_DIR ?= /usr/local

# 编译工具链
CC = gcc
AR = ar

# =============================================================================
# 编译选项
# =============================================================================

# 基础编译选项
CFLAGS = -Wall -Werror -O2 -g
CFLAGS += -Wno-unused-function -Wno-unused-variable
CFLAGS += -D_GNU_SOURCE

# F-Stack相关包含路径
CFLAGS += -I$(FSTACK_DIR)/include
CFLAGS += -I$(DPDK_DIR)/include
CFLAGS += -I$(DPDK_DIR)/include/dpdk

# mbedTLS包含路径
CFLAGS += -I$(MBEDTLS_DIR)/include

# F-Stack配置头文件
CFLAGS += -include $(FSTACK_DIR)/include/ff_config.h

# =============================================================================
# 链接选项
# =============================================================================

# 库搜索路径
LDFLAGS = -L$(FSTACK_DIR)/lib
LDFLAGS += -L$(DPDK_DIR)/lib
LDFLAGS += -L$(MBEDTLS_DIR)/lib

# 链接库（顺序很重要）
LDLIBS = -lfs
LDLIBS += -lmbedtls -lmbedx509 -lmbedcrypto

# DPDK相关库
LDLIBS += -Wl,--whole-archive
LDLIBS += -ldpdk
LDLIBS += -Wl,--no-whole-archive

# 系统库
LDLIBS += -lnuma -lpthread -ldl -lrt -lm

# =============================================================================
# 目标和源文件
# =============================================================================

TARGET = binance_ws_client
SOURCES = binance_ws_client.c
OBJECTS = $(SOURCES:.c=.o)

# =============================================================================
# 构建规则
# =============================================================================

.PHONY: all clean install help

# 默认目标
all: $(TARGET)

# 主程序构建
$(TARGET): $(OBJECTS)
	@echo "链接 $@..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)
	@echo "构建完成: $@"

# 编译源文件
%.o: %.c
	@echo "编译 $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -f $(TARGET) $(OBJECTS)
	@echo "清理完成"

# 安装到系统
install: $(TARGET)
	@echo "安装 $(TARGET) 到 /usr/local/bin/"
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "安装完成"

# 卸载
uninstall:
	@echo "卸载 $(TARGET)..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "卸载完成"

# 显示帮助信息
help:
	@echo "F-Stack + mbedTLS 币安WebSocket客户端"
	@echo "======================================"
	@echo ""
	@echo "使用方法:"
	@echo "  make          - 构建程序"
	@echo "  make clean    - 清理构建文件"
	@echo "  make install  - 安装到系统"
	@echo "  make uninstall- 从系统卸载"
	@echo "  make help     - 显示此帮助信息"
	@echo ""
	@echo "环境变量:"
	@echo "  FSTACK_DIR    - F-Stack安装路径 (默认: /usr/local/fstack)"
	@echo "  DPDK_DIR      - DPDK安装路径 (默认: \$$FSTACK_DIR/dpdk)"
	@echo "  MBEDTLS_DIR   - mbedTLS安装路径 (默认: /usr/local)"
	@echo ""
	@echo "示例:"
	@echo "  make FSTACK_DIR=/opt/fstack MBEDTLS_DIR=/opt/mbedtls"
	@echo ""
	@echo "运行前准备:"
	@echo "  1. 确保DPDK已正确配置huge pages"
	@echo "  2. 绑定网卡到DPDK驱动"
	@echo "  3. 准备F-Stack配置文件"

# =============================================================================
# 调试和检查规则
# =============================================================================

# 显示编译信息
debug:
	@echo "编译配置信息:"
	@echo "=============="
	@echo "CC       = $(CC)"
	@echo "CFLAGS   = $(CFLAGS)"
	@echo "LDFLAGS  = $(LDFLAGS)"
	@echo "LDLIBS   = $(LDLIBS)"
	@echo ""
	@echo "路径配置:"
	@echo "========="
	@echo "FSTACK_DIR  = $(FSTACK_DIR)"
	@echo "DPDK_DIR    = $(DPDK_DIR)"
	@echo "MBEDTLS_DIR = $(MBEDTLS_DIR)"
	@echo ""
	@echo "目标文件:"
	@echo "========="
	@echo "TARGET   = $(TARGET)"
	@echo "SOURCES  = $(SOURCES)"
	@echo "OBJECTS  = $(OBJECTS)"

# 检查依赖
check-deps:
	@echo "检查编译依赖..."
	@echo "=================="
	@echo -n "检查F-Stack头文件: "
	@if [ -f "$(FSTACK_DIR)/include/ff_api.h" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到 $(FSTACK_DIR)/include/ff_api.h"; \
	fi
	@echo -n "检查mbedTLS头文件: "
	@if [ -f "$(MBEDTLS_DIR)/include/mbedtls/ssl.h" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到 $(MBEDTLS_DIR)/include/mbedtls/ssl.h"; \
	fi
	@echo -n "检查F-Stack库文件: "
	@if [ -f "$(FSTACK_DIR)/lib/libfs.a" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到 $(FSTACK_DIR)/lib/libfs.a"; \
	fi
	@echo -n "检查mbedTLS库文件: "
	@if [ -f "$(MBEDTLS_DIR)/lib/libmbedtls.a" ] || [ -f "$(MBEDTLS_DIR)/lib/libmbedtls.so" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到mbedTLS库文件"; \
	fi

# =============================================================================
# 高级构建选项
# =============================================================================

# 调试版本
debug-build: CFLAGS += -DDEBUG -O0
debug-build: $(TARGET)

# 发布版本
release-build: CFLAGS += -DNDEBUG -O3
release-build: $(TARGET)

# 静态链接版本
static-build: LDFLAGS += -static
static-build: $(TARGET)
