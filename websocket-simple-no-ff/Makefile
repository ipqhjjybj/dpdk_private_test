# 编译器设置
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LDFLAGS = 

# mbedtls库路径（根据实际安装位置修改）
MBEDTLS_INCLUDE ?= /usr/local/include
MBEDTLS_LIB ?= /usr/local/lib

# 包含路径和库路径
CXXFLAGS += -I$(MBEDTLS_INCLUDE)
LDFLAGS += -L$(MBEDTLS_LIB)

# 链接库
LDLIBS = -lmbedtls -lmbedx509 -lmbedcrypto -lpthread

# 目标和源文件
TARGET = binance_ws_client
SRCS = binance_ws_client.cpp

# 默认目标
all: $(TARGET)

# 编译规则
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# 清理
clean:
	rm -f $(TARGET)

# 运行
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
