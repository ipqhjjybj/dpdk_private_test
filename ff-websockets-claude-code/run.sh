#!/bin/bash

# F-Stack + mbedTLS 币安WebSocket客户端运行脚本
# 用于简化程序启动和环境配置

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    echo "F-Stack + mbedTLS 币安WebSocket客户端运行脚本"
    echo "=============================================="
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help           显示此帮助信息"
    echo "  -c, --config FILE    指定配置文件 (默认: f-stack.conf)"
    echo "  -b, --build          编译程序"
    echo "  -s, --setup          执行系统设置"
    echo "  -t, --test           测试模式"
    echo "  -v, --verbose        详细输出"
    echo "  --check-deps         检查依赖"
    echo "  --clean              清理构建文件"
    echo ""
    echo "示例:"
    echo "  $0                   # 直接运行程序"
    echo "  $0 -b                # 编译后运行"
    echo "  $0 -s                # 设置环境后运行"
    echo "  $0 -c custom.conf    # 使用自定义配置文件"
}

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此程序需要root权限运行"
        print_info "请使用: sudo $0 $*"
        exit 1
    fi
}

# 检查huge pages配置
check_hugepages() {
    print_info "检查huge pages配置..."
    
    local hugepages_2m=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo "0")
    local hugepages_1g=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || echo "0")
    
    if [[ $hugepages_2m -eq 0 && $hugepages_1g -eq 0 ]]; then
        print_warning "未配置huge pages"
        print_info "正在配置2MB huge pages..."
        echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
        print_success "已配置1024个2MB huge pages"
    else
        print_success "huge pages已配置: 2MB=$hugepages_2m, 1GB=$hugepages_1g"
    fi
}

# 检查DPDK网卡绑定
check_dpdk_binding() {
    print_info "检查DPDK网卡绑定..."
    
    if ! command -v dpdk-devbind.py &> /dev/null; then
        print_warning "dpdk-devbind.py 未找到，跳过网卡检查"
        return
    fi
    
    local bound_devices=$(dpdk-devbind.py --status | grep "drv=uio_pci_generic" | wc -l)
    
    if [[ $bound_devices -eq 0 ]]; then
        print_warning "未找到绑定到DPDK的网卡"
        print_info "请手动绑定网卡到DPDK驱动:"
        print_info "  dpdk-devbind.py --status"
        print_info "  dpdk-devbind.py --bind=uio_pci_generic <PCI_ADDRESS>"
    else
        print_success "找到 $bound_devices 个绑定到DPDK的网卡"
    fi
}

# 系统设置
setup_system() {
    print_info "执行系统设置..."
    
    # 加载必要的内核模块
    print_info "加载内核模块..."
    modprobe uio || print_warning "无法加载uio模块"
    modprobe uio_pci_generic || print_warning "无法加载uio_pci_generic模块"
    
    # 配置huge pages
    check_hugepages
    
    # 检查网卡绑定
    check_dpdk_binding
    
    print_success "系统设置完成"
}

# 编译程序
build_program() {
    print_info "编译程序..."
    
    if [[ ! -f "Makefile" ]]; then
        print_error "未找到Makefile"
        exit 1
    fi
    
    make clean
    make
    
    if [[ -f "binance_ws_client" ]]; then
        print_success "编译完成"
    else
        print_error "编译失败"
        exit 1
    fi
}

# 检查依赖
check_dependencies() {
    print_info "检查编译依赖..."
    make check-deps
}

# 运行程序
run_program() {
    local config_file="$1"
    local verbose="$2"
    
    print_info "启动币安WebSocket客户端..."
    
    if [[ ! -f "binance_ws_client" ]]; then
        print_error "程序文件不存在，请先编译"
        print_info "运行: $0 -b"
        exit 1
    fi
    
    if [[ ! -f "$config_file" ]]; then
        print_error "配置文件不存在: $config_file"
        exit 1
    fi
    
    print_info "使用配置文件: $config_file"
    
    # 设置信号处理
    trap 'print_info "收到中断信号，正在退出..."; exit 0' INT TERM
    
    if [[ "$verbose" == "true" ]]; then
        ./binance_ws_client --conf="$config_file" --verbose
    else
        ./binance_ws_client --conf="$config_file"
    fi
}

# 测试模式
test_mode() {
    print_info "进入测试模式..."
    
    # 检查依赖
    check_dependencies
    
    # 检查系统配置
    print_info "检查系统配置..."
    check_hugepages
    check_dpdk_binding
    
    # 检查网络连通性
    print_info "检查网络连通性..."
    if ping -c 1 stream.binance.com &> /dev/null; then
        print_success "可以连接到币安服务器"
    else
        print_warning "无法连接到币安服务器"
    fi
    
    print_success "测试模式完成"
}

# 主函数
main() {
    local config_file="f-stack.conf"
    local build_flag=false
    local setup_flag=false
    local test_flag=false
    local verbose=false
    local check_deps_flag=false
    local clean_flag=false
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -b|--build)
                build_flag=true
                shift
                ;;
            -s|--setup)
                setup_flag=true
                shift
                ;;
            -t|--test)
                test_flag=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            --check-deps)
                check_deps_flag=true
                shift
                ;;
            --clean)
                clean_flag=true
                shift
                ;;
            *)
                print_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 显示程序标题
    echo "================================================"
    echo "F-Stack + mbedTLS 币安WebSocket客户端"
    echo "================================================"
    
    # 执行清理
    if [[ "$clean_flag" == "true" ]]; then
        print_info "清理构建文件..."
        make clean
        print_success "清理完成"
        exit 0
    fi
    
    # 检查依赖
    if [[ "$check_deps_flag" == "true" ]]; then
        check_dependencies
        exit 0
    fi
    
    # 测试模式
    if [[ "$test_flag" == "true" ]]; then
        test_mode
        exit 0
    fi
    
    # 检查root权限
    check_root
    
    # 系统设置
    if [[ "$setup_flag" == "true" ]]; then
        setup_system
    fi
    
    # 编译程序
    if [[ "$build_flag" == "true" ]]; then
        build_program
    fi
    
    # 运行程序
    run_program "$config_file" "$verbose"
}

# 执行主函数
main "$@"
