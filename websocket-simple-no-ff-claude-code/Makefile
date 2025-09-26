# 轻量级币安WebSocket客户端 Makefile (C语言版本)

# 编译器配置
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
CFLAGS += -D_POSIX_C_SOURCE=200809L

# mbedTLS库路径配置
MBEDTLS_INCLUDE ?= /usr/local/include
MBEDTLS_LIB ?= /usr/local/lib

# 包含路径和库路径
CFLAGS += -I$(MBEDTLS_INCLUDE)
LDFLAGS = -L$(MBEDTLS_LIB)

# 链接库
LDLIBS = -lmbedtls -lmbedx509 -lmbedcrypto

# 目标和源文件
TARGET = binance_ws_client
SOURCES = binance_ws_client.c
OBJECTS = $(SOURCES:.c=.o)

# 默认目标
.PHONY: all clean run install help debug

all: $(TARGET)

# 编译规则
$(TARGET): $(OBJECTS)
	@echo "链接 $@..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(LDLIBS)
	@echo "编译完成: $@"

%.o: %.c
	@echo "编译 $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -f $(TARGET) $(OBJECTS)
	@echo "清理完成"

# 运行程序
run: $(TARGET)
	@echo "运行 $(TARGET)..."
	./$(TARGET)

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

# 调试版本
debug: CFLAGS += -g -DDEBUG -O0
debug: $(TARGET)

# 检查依赖
check-deps:
	@echo "检查编译依赖..."
	@echo "=================="
	@echo -n "检查mbedTLS头文件: "
	@if [ -f "$(MBEDTLS_INCLUDE)/mbedtls/ssl.h" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到 $(MBEDTLS_INCLUDE)/mbedtls/ssl.h"; \
	fi
	@echo -n "检查mbedTLS库文件: "
	@if [ -f "$(MBEDTLS_LIB)/libmbedtls.a" ] || [ -f "$(MBEDTLS_LIB)/libmbedtls.so" ]; then \
		echo "✓ 找到"; \
	else \
		echo "✗ 未找到mbedTLS库文件"; \
	fi
	@echo -n "检查编译器: "
	@if command -v $(CC) >/dev/null 2>&1; then \
		echo "✓ $(CC) 可用"; \
	else \
		echo "✗ $(CC) 未找到"; \
	fi

# 显示帮助信息
help:
	@echo "轻量级币安WebSocket客户端 (C语言版本)"
	@echo "====================================="
	@echo ""
	@echo "使用方法:"
	@echo "  make          - 编译程序"
	@echo "  make clean    - 清理构建文件"
	@echo "  make run      - 编译并运行程序"
	@echo "  make debug    - 编译调试版本"
	@echo "  make install  - 安装到系统"
	@echo "  make uninstall- 从系统卸载"
	@echo "  make check-deps- 检查编译依赖"
	@echo "  make help     - 显示此帮助信息"
	@echo ""
	@echo "环境变量:"
	@echo "  MBEDTLS_INCLUDE - mbedTLS头文件路径 (默认: /usr/local/include)"
	@echo "  MBEDTLS_LIB     - mbedTLS库文件路径 (默认: /usr/local/lib)"
	@echo ""
	@echo "示例:"
	@echo "  make MBEDTLS_INCLUDE=/opt/mbedtls/include MBEDTLS_LIB=/opt/mbedtls/lib"
	@echo ""
	@echo "依赖要求:"
	@echo "  - GCC 编译器"
	@echo "  - mbedTLS 3.0+ 库"
	@echo "  - 网络连接（用于连接币安服务器）"

# 显示编译信息
info:
	@echo "编译配置信息:"
	@echo "=============="
	@echo "CC       = $(CC)"
	@echo "CFLAGS   = $(CFLAGS)"
	@echo "LDFLAGS  = $(LDFLAGS)"
	@echo "LDLIBS   = $(LDLIBS)"
	@echo ""
	@echo "路径配置:"
	@echo "========="
	@echo "MBEDTLS_INCLUDE = $(MBEDTLS_INCLUDE)"
	@echo "MBEDTLS_LIB     = $(MBEDTLS_LIB)"
	@echo ""
	@echo "目标文件:"
	@echo "========="
	@echo "TARGET   = $(TARGET)"
	@echo "SOURCES  = $(SOURCES)"
	@echo "OBJECTS  = $(OBJECTS)"

# 测试网络连接
test-network:
	@echo "测试网络连接..."
	@echo "================"
	@echo -n "测试DNS解析: "
	@if nslookup $(BINANCE_HOST) >/dev/null 2>&1; then \
		echo "✓ 可以解析 $(BINANCE_HOST)"; \
	else \
		echo "✗ 无法解析 $(BINANCE_HOST)"; \
	fi
	@echo -n "测试网络连通性: "
	@if ping -c 1 -W 3 $(BINANCE_HOST) >/dev/null 2>&1; then \
		echo "✓ 可以连接到 $(BINANCE_HOST)"; \
	else \
		echo "✗ 无法连接到 $(BINANCE_HOST)"; \
	fi

# 静态分析
analyze: $(SOURCES)
	@echo "运行静态分析..."
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --std=c99 $(SOURCES); \
	else \
		echo "cppcheck 未安装，跳过静态分析"; \
	fi

# 内存检查版本（需要valgrind）
memcheck: debug
	@echo "运行内存检查..."
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET); \
	else \
		echo "valgrind 未安装，无法进行内存检查"; \
	fi
