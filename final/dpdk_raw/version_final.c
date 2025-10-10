/*
 * 精简版DPDK WebSocket客户端 - 绕过F-Stack直接使用DPDK
 *
 * 架构优化：
 * 1. DPDK直接收包 + 硬件时间戳提取（零拷贝）
 * 2. 最小化TCP状态机（仅客户端必需状态）
 * 3. mbedTLS TLS解密（零缓冲区拷贝）
 * 4. WebSocket解帧 + 币安数据解析
 *
 * 延迟优化目标：< 100μs (vs F-Stack 270μs)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sched.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

// 性能优化宏
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// DPDK配置
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PKT_BURST 32

// 网络配置
//#define BINANCE_SERVER_IP "54.64.217.188"
#define BINANCE_SERVER_IP "52.193.85.106"
#define BINANCE_SERVER_PORT 443
#define LOCAL_IP "172.35.33.174"
#define LOCAL_PORT 8000
#define GATEWAY_IP "172.35.32.1"

// WebSocket帧类型
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA
#define WS_OPCODE_CLOSE 0x8

// TCP连接状态（精简版）
typedef enum {
    TCP_CLOSED = 0,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT
} tcp_state_t;

// TLS连接状态
typedef enum {
    TLS_INIT = 0,
    TLS_HANDSHAKING,
    TLS_CONNECTED,
    WS_HANDSHAKE_SENT,
    WS_CONNECTED
} tls_state_t;

// 连接上下文（单连接优化）
typedef struct {
    // TCP状态
    tcp_state_t tcp_state;
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t init_seq;

    // TLS上下文
    tls_state_t tls_state;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // 接收缓冲区（用于TCP重组和TLS解密）
    unsigned char rx_buffer[131072];  // 128KB，支持更多交易对
    int rx_buffer_len;

    // WebSocket缓冲区
    unsigned char ws_buffer[262144];  // 256KB，支持更多交易对
    int ws_buffer_len;

    // 时间戳记录
    uint64_t last_rx_timestamp_ns;

    // MAC地址
    struct rte_ether_addr local_mac;
    struct rte_ether_addr remote_mac;

    // ARP状态
    int arp_resolved;
    uint32_t gateway_ip;


} connection_ctx_t;

// 全局变量
static uint16_t port_id = 0;
static struct rte_mempool *mbuf_pool = NULL;
static connection_ctx_t *conn_ctx = NULL;
static volatile int force_quit = 0;

// 延迟统计
typedef struct {
    double total_latency;
    double min_latency;
    double max_latency;
    int count;
    double total_rx_latency;
    double min_rx_latency;
    double max_rx_latency;
} latency_stats_t;

static latency_stats_t latency_stats = {0.0, 999999.0, 0.0, 0, 0.0, 999999.0, 0.0};

// 延迟文件
static FILE *latency_file = NULL;

// 全局缓冲区（避免栈分配，多个函数复用）
static unsigned char g_ws_handshake_response[81920];
static unsigned char g_tls_decrypted_data[163840];
static unsigned char g_websocket_frame_send[81920];

// 获取高精度时间戳（微秒）
static inline double get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

// 获取数据包接收时间戳（软件时间戳）
// 注意：DPDK 23.11硬件时间戳需要动态字段API，这里简化为软件时间戳
static inline uint64_t get_hw_timestamp_ns(struct rte_mbuf *m) {
    // 使用DPDK时钟周期转换为纳秒
    // 这是接收到包时立即获取的软件时间戳，延迟 < 100ns
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 绑定CPU核心
int bind_to_cpu_core(int core_id) {
   cpu_set_t cpuset;
   pid_t pid = getpid();

   // 清空CPU集合
   CPU_ZERO(&cpuset);

   // 设置要绑定的CPU核心
   CPU_SET(core_id, &cpuset);

   // 执行CPU绑定
   if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
       perror("sched_setaffinity failed");
       return -1;
   }

   printf("Successfully bound process to CPU core %d\n", core_id);
   return 0;
}

// 函数前向声明
static int send_tcp_packet(uint8_t flags, const uint8_t *payload, uint16_t payload_len);

// 计算TCP校验和（使用DPDK内置函数）
static inline uint16_t tcp_checksum(struct rte_ipv4_hdr *ip_hdr, struct rte_tcp_hdr *tcp_hdr) {
    tcp_hdr->cksum = 0;
    return rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);
}

// 发送Gratuitous ARP（宣告自己的IP和MAC）
static int send_gratuitous_arp(void) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (unlikely(mbuf == NULL)) {
        return -1;
    }

    // 构造以太网头（广播）
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    memset(&eth_hdr->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN); // 广播
    rte_ether_addr_copy(&conn_ctx->local_mac, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // 构造ARP头（Gratuitous ARP: 请求自己的IP）
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = 4;
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    // Gratuitous ARP: 源IP和目标IP都是自己的IP
    rte_ether_addr_copy(&conn_ctx->local_mac, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = conn_ctx->local_ip;
    memset(&arp_hdr->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip = conn_ctx->local_ip;  // 关键：询问自己的IP

    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    mbuf->pkt_len = mbuf->data_len;

    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (nb_tx == 0) {
        printf("警告: Gratuitous ARP发送失败\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    printf("DEBUG: 已发送Gratuitous ARP，宣告IP: %u.%u.%u.%u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           (ntohl(conn_ctx->local_ip) >> 24) & 0xFF,
           (ntohl(conn_ctx->local_ip) >> 16) & 0xFF,
           (ntohl(conn_ctx->local_ip) >> 8) & 0xFF,
           ntohl(conn_ctx->local_ip) & 0xFF,
           conn_ctx->local_mac.addr_bytes[0],
           conn_ctx->local_mac.addr_bytes[1],
           conn_ctx->local_mac.addr_bytes[2],
           conn_ctx->local_mac.addr_bytes[3],
           conn_ctx->local_mac.addr_bytes[4],
           conn_ctx->local_mac.addr_bytes[5]);

    return 0;
}

// 发送ARP请求（获取网关MAC地址）
static int send_arp_request(uint32_t target_ip) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (unlikely(mbuf == NULL)) {
        return -1;
    }

    // 构造以太网头（广播）
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    memset(&eth_hdr->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN); // 广播地址
    rte_ether_addr_copy(&conn_ctx->local_mac, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // 构造ARP头
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = 4;
    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    // 填充ARP数据
    rte_ether_addr_copy(&conn_ctx->local_mac, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = conn_ctx->local_ip;
    memset(&arp_hdr->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN); // 目标MAC未知
    arp_hdr->arp_data.arp_tip = target_ip;

    // 设置mbuf长度
    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    mbuf->pkt_len = mbuf->data_len;

    // 发送ARP请求
    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (nb_tx == 0) {
        printf("警告: ARP请求发送失败\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    printf("DEBUG: 已发送ARP请求，询问IP: %u.%u.%u.%u\n",
           (ntohl(target_ip) >> 24) & 0xFF,
           (ntohl(target_ip) >> 16) & 0xFF,
           (ntohl(target_ip) >> 8) & 0xFF,
           ntohl(target_ip) & 0xFF);

    return 0;
}

// 处理ARP请求并发送响应
static void handle_arp_packet(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

    uint16_t opcode = rte_be_to_cpu_16(arp_hdr->arp_opcode);

    // 处理ARP回复（更新网关MAC地址）
    if (opcode == RTE_ARP_OP_REPLY) {
        // 检查是否是网关的ARP回复
        if (arp_hdr->arp_data.arp_sip == conn_ctx->gateway_ip) {
            rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &conn_ctx->remote_mac);
            conn_ctx->arp_resolved = 1;
            printf("DEBUG: 收到网关ARP回复，MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   conn_ctx->remote_mac.addr_bytes[0],
                   conn_ctx->remote_mac.addr_bytes[1],
                   conn_ctx->remote_mac.addr_bytes[2],
                   conn_ctx->remote_mac.addr_bytes[3],
                   conn_ctx->remote_mac.addr_bytes[4],
                   conn_ctx->remote_mac.addr_bytes[5]);

            // ARP解析完成，发起TCP连接
            if (conn_ctx->tcp_state == TCP_CLOSED) {
                conn_ctx->init_seq = rte_rand();
                conn_ctx->seq_num = conn_ctx->init_seq;
                conn_ctx->tcp_state = TCP_SYN_SENT;
                send_tcp_packet(RTE_TCP_SYN_FLAG, NULL, 0);
                conn_ctx->seq_num++;
                printf("已发送SYN包，等待连接...\n");
            }
        }
        return;
    }

    // 处理ARP请求
    if (opcode != RTE_ARP_OP_REQUEST) {
        return;
    }

    // 检查是否是询问我们的IP
    if (arp_hdr->arp_data.arp_tip != conn_ctx->local_ip) {
        return;
    }

    printf("DEBUG: 收到ARP请求\n");
    printf("  询问IP: %u.%u.%u.%u\n",
           (ntohl(arp_hdr->arp_data.arp_tip) >> 24) & 0xFF,
           (ntohl(arp_hdr->arp_data.arp_tip) >> 16) & 0xFF,
           (ntohl(arp_hdr->arp_data.arp_tip) >> 8) & 0xFF,
           ntohl(arp_hdr->arp_data.arp_tip) & 0xFF);
    printf("  请求者MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_hdr->arp_data.arp_sha.addr_bytes[0],
           arp_hdr->arp_data.arp_sha.addr_bytes[1],
           arp_hdr->arp_data.arp_sha.addr_bytes[2],
           arp_hdr->arp_data.arp_sha.addr_bytes[3],
           arp_hdr->arp_data.arp_sha.addr_bytes[4],
           arp_hdr->arp_data.arp_sha.addr_bytes[5]);
    printf("  请求者IP: %u.%u.%u.%u\n",
           (ntohl(arp_hdr->arp_data.arp_sip) >> 24) & 0xFF,
           (ntohl(arp_hdr->arp_data.arp_sip) >> 16) & 0xFF,
           (ntohl(arp_hdr->arp_data.arp_sip) >> 8) & 0xFF,
           ntohl(arp_hdr->arp_data.arp_sip) & 0xFF);

    // 分配新的mbuf用于ARP回复
    struct rte_mbuf *reply = rte_pktmbuf_alloc(mbuf_pool);
    if (unlikely(reply == NULL)) {
        printf("警告: 无法分配mbuf用于ARP回复\n");
        return;
    }

    // 构造以太网头
    struct rte_ether_hdr *reply_eth = rte_pktmbuf_mtod(reply, struct rte_ether_hdr *);
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &reply_eth->dst_addr);
    rte_ether_addr_copy(&conn_ctx->local_mac, &reply_eth->src_addr);
    reply_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // 构造ARP头
    struct rte_arp_hdr *reply_arp = (struct rte_arp_hdr *)(reply_eth + 1);
    reply_arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    reply_arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    reply_arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    reply_arp->arp_plen = 4;
    reply_arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    // 填充ARP数据
    rte_ether_addr_copy(&conn_ctx->local_mac, &reply_arp->arp_data.arp_sha);
    reply_arp->arp_data.arp_sip = conn_ctx->local_ip;
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &reply_arp->arp_data.arp_tha);
    reply_arp->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;

    // 设置mbuf长度
    reply->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    reply->pkt_len = reply->data_len;

    // 发送ARP回复
    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &reply, 1);
    if (nb_tx == 0) {
        printf("警告: ARP回复发送失败\n");
        rte_pktmbuf_free(reply);
    } else {
        printf("DEBUG: 已发送ARP回复\n");
        printf("  ARP opcode: %u (应该是2=reply)\n", rte_be_to_cpu_16(reply_arp->arp_opcode));
        printf("  发送者MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               reply_arp->arp_data.arp_sha.addr_bytes[0],
               reply_arp->arp_data.arp_sha.addr_bytes[1],
               reply_arp->arp_data.arp_sha.addr_bytes[2],
               reply_arp->arp_data.arp_sha.addr_bytes[3],
               reply_arp->arp_data.arp_sha.addr_bytes[4],
               reply_arp->arp_data.arp_sha.addr_bytes[5]);
        printf("  发送者IP: %u.%u.%u.%u\n",
               (ntohl(reply_arp->arp_data.arp_sip) >> 24) & 0xFF,
               (ntohl(reply_arp->arp_data.arp_sip) >> 16) & 0xFF,
               (ntohl(reply_arp->arp_data.arp_sip) >> 8) & 0xFF,
               ntohl(reply_arp->arp_data.arp_sip) & 0xFF);
        printf("  目标MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               reply_arp->arp_data.arp_tha.addr_bytes[0],
               reply_arp->arp_data.arp_tha.addr_bytes[1],
               reply_arp->arp_data.arp_tha.addr_bytes[2],
               reply_arp->arp_data.arp_tha.addr_bytes[3],
               reply_arp->arp_data.arp_tha.addr_bytes[4],
               reply_arp->arp_data.arp_tha.addr_bytes[5]);
        printf("  目标IP: %u.%u.%u.%u\n",
               (ntohl(reply_arp->arp_data.arp_tip) >> 24) & 0xFF,
               (ntohl(reply_arp->arp_data.arp_tip) >> 16) & 0xFF,
               (ntohl(reply_arp->arp_data.arp_tip) >> 8) & 0xFF,
               ntohl(reply_arp->arp_data.arp_tip) & 0xFF);
    }
}

// 发送TCP数据包（精简版 - 无重传队列）
static int send_tcp_packet(uint8_t flags, const uint8_t *payload, uint16_t payload_len) {
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint8_t *data;
    mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (unlikely(mbuf == NULL)) {
        return -1;
    }

    // 构造以太网帧
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_ether_addr_copy(&conn_ctx->remote_mac, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&conn_ctx->local_mac, &eth_hdr->src_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // 构造IP头
    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45; // IPv4, 20字节头
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                             sizeof(struct rte_tcp_hdr) + payload_len);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_TCP;
    ip_hdr->src_addr = conn_ctx->local_ip;
    ip_hdr->dst_addr = conn_ctx->remote_ip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    // 构造TCP头
    tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
    tcp_hdr->src_port = rte_cpu_to_be_16(conn_ctx->local_port);
    tcp_hdr->dst_port = rte_cpu_to_be_16(conn_ctx->remote_port);
    tcp_hdr->sent_seq = rte_cpu_to_be_32(conn_ctx->seq_num);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(conn_ctx->ack_num);
    tcp_hdr->data_off = (5 << 4); // 20字节TCP头
    tcp_hdr->tcp_flags = flags;
    tcp_hdr->rx_win = rte_cpu_to_be_16(65535);
    tcp_hdr->cksum = 0;
    tcp_hdr->tcp_urp = 0;

    // 拷贝payload
    if (payload_len > 0) {
        data = (uint8_t *)(tcp_hdr + 1);
        rte_memcpy(data, payload, payload_len);
        conn_ctx->seq_num += payload_len;
    }
    //printf("[send_tcp_packet] pre tcp_checksum\n");

    // 计算TCP校验和
    tcp_hdr->cksum = tcp_checksum(ip_hdr, tcp_hdr);
    //printf("[send_tcp_packet] after tcp_checksum\n");
    // 设置mbuf长度
    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr) + payload_len;
    mbuf->pkt_len = mbuf->data_len;
    //printf("[send_tcp_packet] after mbuf->data_len:%d, pkt_len:%d\n", mbuf->data_len, mbuf->pkt_len);
    // 发送数据包 - 添加调试信息
    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (nb_tx == 0) {
        printf("警告: TX发送失败\n");
        rte_pktmbuf_free(mbuf);
        return -1;
    }
    //printf("[send_tcp_packet] after rte_eth_tx_burst\n");


    return 0;
}

// mbedTLS发送回调（通过DPDK发送）
static int tls_send_callback(void *ctx, const unsigned char *buf, size_t len) {
    int ret = send_tcp_packet(RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, buf, len);
    return ret < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : len;
}

// mbedTLS接收回调（从缓冲区读取）
static int tls_recv_callback(void *ctx, unsigned char *buf, size_t len) {
    connection_ctx_t *conn = (connection_ctx_t *)ctx;

    if (conn->rx_buffer_len == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    size_t to_copy = (len < conn->rx_buffer_len) ? len : conn->rx_buffer_len;
    rte_memcpy(buf, conn->rx_buffer, to_copy);

    // 移动剩余数据
    if (to_copy < conn->rx_buffer_len) {
        memmove(conn->rx_buffer, conn->rx_buffer + to_copy, conn->rx_buffer_len - to_copy);
    }
    conn->rx_buffer_len -= to_copy;

    return to_copy;
}

// 处理币安交易数据（与原版相同）
static void process_trade_data(const unsigned char *data, int len, uint64_t hw_timestamp_ns);

// WebSocket帧解析
static int parse_websocket_frame(const unsigned char *buffer, int len,
                                unsigned char **payload, int *payload_len, int *opcode);

// 发送WebSocket Pong
static void send_websocket_pong(const unsigned char *payload, int len);

// 处理TCP数据包
static void process_tcp_packet(struct rte_mbuf *m) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint8_t *tcp_data;
    uint16_t tcp_data_len;

    // 提取硬件时间戳
    uint64_t hw_ts = get_hw_timestamp_ns(m);
    if (hw_ts > 0) {
        conn_ctx->last_rx_timestamp_ns = hw_ts;
    }

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr + ((ip_hdr->version_ihl & 0x0F) * 4));

    uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
    uint32_t ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);
    uint8_t flags = tcp_hdr->tcp_flags;

    tcp_data = (uint8_t *)tcp_hdr + ((tcp_hdr->data_off >> 4) * 4);
    tcp_data_len = rte_be_to_cpu_16(ip_hdr->total_length) -
                   ((ip_hdr->version_ihl & 0x0F) * 4) -
                   ((tcp_hdr->data_off >> 4) * 4);


    // 状态机处理

    switch (conn_ctx->tcp_state) {
        case TCP_SYN_SENT:
            printf("[TCP_SYN_SENT]\n");
            if (flags & RTE_TCP_SYN_FLAG && flags & RTE_TCP_ACK_FLAG) {
                printf("收到SYN-ACK！\n");
                conn_ctx->ack_num = seq + 1;
                conn_ctx->tcp_state = TCP_ESTABLISHED;
                send_tcp_packet(RTE_TCP_ACK_FLAG, NULL, 0);
                printf("TCP连接建立成功\n");

                // 开始TLS握手
                conn_ctx->tls_state = TLS_HANDSHAKING;
                mbedtls_ssl_handshake(&conn_ctx->ssl);
            } else if (flags & RTE_TCP_ACK_FLAG) {
                // 收到纯ACK或其他包，说明服务器认为连接已存在
                // 发送RST重置连接
                printf("WARNING: TCP_SYN_SENT状态收到ACK (flags=0x%02x)，发送RST重置连接\n", flags);
                conn_ctx->seq_num = ack;  // 使用对方的ACK作为我们的SEQ
                send_tcp_packet(RTE_TCP_RST_FLAG, NULL, 0);

                // 重新发送SYN
                conn_ctx->seq_num = conn_ctx->init_seq;
                send_tcp_packet(RTE_TCP_SYN_FLAG, NULL, 0);
                conn_ctx->seq_num++;
                printf("已重新发送SYN\n");
            } else {
                printf("WARNING: TCP_SYN_SENT状态收到未知包，flags=0x%02x\n", flags);
            }
            break;

        case TCP_ESTABLISHED:
            if (tcp_data_len > 0) {
                // 检查是否是新数据（避免处理重复包）
                if (seq != conn_ctx->ack_num) {
                    printf("DEBUG: 跳过旧数据或重复包 seq=%u, expected=%u\n", seq, conn_ctx->ack_num);
                    break;
                }
                // 数据包 - 添加到接收缓冲区
                if (conn_ctx->rx_buffer_len + tcp_data_len < sizeof(conn_ctx->rx_buffer)) {
                    rte_memcpy(conn_ctx->rx_buffer + conn_ctx->rx_buffer_len,
                              tcp_data, tcp_data_len);
                    conn_ctx->rx_buffer_len += tcp_data_len;
                    conn_ctx->ack_num = seq + tcp_data_len;
                    send_tcp_packet(RTE_TCP_ACK_FLAG, NULL, 0);

                    // 如果TLS还没开始，启动TLS握手
                    if (conn_ctx->tls_state == TLS_INIT) {
                        printf("启动TLS握手...\n");
                        conn_ctx->tls_state = TLS_HANDSHAKING;
                    }

                    // TLS解密处理
                    if (conn_ctx->tls_state == TLS_HANDSHAKING) {
                        int ret = mbedtls_ssl_handshake(&conn_ctx->ssl);
                        printf("[ret = mbedtls_ssl_handshake(&conn_ctx->ssl)] = %d\n", ret);
                        if (ret == 0) {
                            printf("✓ TLS握手完成\n");

                            // 发送WebSocket握手请求
                            const char *ws_handshake =
                                "GET /stream?streams=btcusdt@trade/ethusdt@trade/bchusdt@trade/xrpusdt@trade/ltcusdt@trade/trxusdt@trade/etcusdt@trade/linkusdt@trade/xlmusdt@trade/adausdt@trade/xmrusdt@trade/dashusdt@trade/zecusdt@trade/xtzusdt@trade/bnbusdt@trade/atomusdt@trade/ontusdt@trade/iotausdt@trade/batusdt@trade/vetusdt@trade/neousdt@trade/qtumusdt@trade/iostusdt@trade/thetausdt@trade/algousdt@trade/zilusdt@trade/kncusdt@trade/zrxusdt@trade/compusdt@trade/dogeusdt@trade/sxpusdt@trade/kavausdt@trade/bandusdt@trade/rlcusdt@trade/snxusdt@trade/dotusdt@trade/yfiusdt@trade/crvusdt@trade/trbusdt@trade/runeusdt@trade/sushiusdt@trade/egldusdt@trade/solusdt@trade/icxusdt@trade/storjusdt@trade/uniusdt@trade/avaxusdt@trade/enjusdt@trade/flmusdt@trade/ksmusdt@trade/nearusdt@trade/aaveusdt@trade/filusdt@trade/rsrusdt@trade/lrcusdt@trade/belusdt@trade/axsusdt@trade/zenusdt@trade/sklusdt@trade/grtusdt@trade/1inchusdt@trade/chzusdt@trade/sandusdt@trade/ankrusdt@trade/rvnusdt@trade/sfpusdt@trade/cotiusdt@trade/chrusdt@trade/manausdt@trade/aliceusdt@trade/hbarusdt@trade/oneusdt@trade/dentusdt@trade/celrusdt@trade/hotusdt@trade/mtlusdt@trade/ognusdt@trade/nknusdt@trade/1000shibusdt@trade/bakeusdt@trade/gtcusdt@trade/btcdomusdt@trade/iotxusdt@trade/c98usdt@trade/maskusdt@trade/atausdt@trade/dydxusdt@trade/1000xecusdt@trade/galausdt@trade/celousdt@trade/arusdt@trade/arpausdt@trade/ctsiusdt@trade/lptusdt@trade/ensusdt@trade/peopleusdt@trade/roseusdt@trade/duskusdt@trade/flowusdt@trade/imxusdt@trade/api3usdt@trade/gmtusdt@trade/apeusdt@trade/woousdt@trade/jasmyusdt@trade/opusdt@trade/injusdt@trade/stgusdt@trade/spellusdt@trade/1000luncusdt@trade/luna2usdt@trade/ldousdt@trade/icpusdt@trade/aptusdt@trade/qntusdt@trade/fetusdt@trade/fxsusdt@trade/hookusdt@trade/magicusdt@trade/tusdt@trade/highusdt@trade/minausdt@trade/astrusdt@trade/phbusdt@trade/gmxusdt@trade/cfxusdt@trade/stxusdt@trade/achusdt@trade/ssvusdt@trade/ckbusdt@trade/perpusdt@trade/truusdt@trade/lqtyusdt@trade/usdcusdt@trade/idusdt@trade/arbusdt@trade/joeusdt@trade/tlmusdt@trade/rdntusdt@trade/hftusdt@trade/xvsusdt@trade/ethbtc@trade/blurusdt@trade/eduusdt@trade/suiusdt@trade/1000pepeusdt@trade/1000flokiusdt@trade/umausdt@trade/nmrusdt@trade/mavusdt@trade/xvgusdt@trade/wldusdt@trade/pendleusdt@trade/arkmusdt@trade/agldusdt@trade/yggusdt@trade/dodoxusdt@trade/bntusdt@trade/oxtusdt@trade/seiusdt@trade/cyberusdt@trade/hifiusdt@trade/arkusdt@trade/bicousdt@trade/bigtimeusdt@trade/waxpusdt@trade/bsvusdt@trade/rifusdt@trade/polyxusdt@trade/gasusdt@trade/powrusdt@trade/tiausdt@trade/cakeusdt@trade/memeusdt@trade/twtusdt@trade/tokenusdt@trade/ordiusdt@trade/steemusdt@trade/ilvusdt@trade/ntrnusdt@trade/kasusdt@trade/beamxusdt@trade/1000bonkusdt@trade/pythusdt@trade/superusdt@trade/ustcusdt@trade/ongusdt@trade/ethwusdt@trade/jtousdt@trade/1000satsusdt@trade/auctionusdt@trade/1000ratsusdt@trade/aceusdt@trade/movrusdt@trade/nfpusdt@trade/btcusdc@trade/ethusdc@trade/bnbusdc@trade/solusdc@trade/xrpusdc@trade HTTP/1.1\r\n"
                                "Host: fstream.binance.com\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "User-Agent: DPDK-Raw-Client/1.0\r\n\r\n";
                               
                           // const char *ws_handshake =
                           //      "GET /stream?streams=btcusdt@trade/ethusdt@trade/bchusdt@trade/xrpusdt@trade/ltcusdt@trade/trxusdt@trade/etcusdt@trade/linkusdt@trade/xlmusdt@trade/adausdt@trade/xmrusdt@trade/dashusdt@trade/zecusdt@trade/xtzusdt@trade/bnbusdt@trade HTTP/1.1\r\n"
                           //      "Host: fstream.binance.com\r\n"
                           //      "Upgrade: websocket\r\n"
                           //      "Connection: Upgrade\r\n"
                           //      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                           //      "Sec-WebSocket-Version: 13\r\n"
                           //      "User-Agent: DPDK-Raw-Client/1.0\r\n\r\n";

                            int ws_ret = mbedtls_ssl_write(&conn_ctx->ssl,
                                                          (unsigned char *)ws_handshake,
                                                          strlen(ws_handshake));
                            if (ws_ret > 0) {
                                printf("✓ WebSocket握手请求已发送 (%d字节)\n", ws_ret);
                                conn_ctx->tls_state = WS_HANDSHAKE_SENT;
                            } else {
                                printf("✗ WebSocket握手发送失败: %d\n", ws_ret);
                            }
                        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                            char error_buf[100];
                            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
                            printf("✗ TLS握手错误: -0x%04x (%s)\n", -ret, error_buf);
                        }
                    } else if (conn_ctx->tls_state == WS_HANDSHAKE_SENT) {
                        // 读取WebSocket握手响应（使用全局缓冲区）
                        int ret = mbedtls_ssl_read(&conn_ctx->ssl, g_ws_handshake_response, sizeof(g_ws_handshake_response));
                        if (ret > 0) {
                            // 查找HTTP响应头结束标记 \r\n\r\n
                            for (int i = 0; i < ret - 3; i++) {
                                if (g_ws_handshake_response[i] == '\r' && g_ws_handshake_response[i+1] == '\n' &&
                                    g_ws_handshake_response[i+2] == '\r' && g_ws_handshake_response[i+3] == '\n') {
                                    printf("✓ WebSocket握手完成\n");
                                    conn_ctx->tls_state = WS_CONNECTED;

                                    // 如果响应后还有数据，需要处理
                                    int remaining = ret - (i + 4);
                                    if (remaining > 0) {
                                        rte_memcpy(conn_ctx->ws_buffer, g_ws_handshake_response + i + 4, remaining);
                                        conn_ctx->ws_buffer_len = remaining;
                                    }
                                    break;
                                }
                            }
                        }
                    } else if (conn_ctx->tls_state == WS_CONNECTED) {
                        // 读取解密后的数据（使用全局缓冲区）
                        int ret = mbedtls_ssl_read(&conn_ctx->ssl, g_tls_decrypted_data, sizeof(g_tls_decrypted_data));
                        if (ret > 0) {
                            // 添加到WebSocket缓冲区
                            if (conn_ctx->ws_buffer_len + ret < sizeof(conn_ctx->ws_buffer)) {
                                rte_memcpy(conn_ctx->ws_buffer + conn_ctx->ws_buffer_len,
                                          g_tls_decrypted_data, ret);
                                conn_ctx->ws_buffer_len += ret;

                                // 解析WebSocket帧（循环处理缓冲区中的所有帧）
                                while (conn_ctx->ws_buffer_len > 0) {
                                    unsigned char *payload;
                                    int payload_len, opcode;
                                    int frame_size = parse_websocket_frame(conn_ctx->ws_buffer,
                                                                conn_ctx->ws_buffer_len,
                                                                &payload, &payload_len, &opcode);
                                    if (frame_size > 0) {
                                        if (opcode == WS_OPCODE_TEXT) {
                                            process_trade_data(payload, payload_len, hw_ts);
                                        } else if (opcode == WS_OPCODE_PING) {
                                            send_websocket_pong(payload, payload_len);
                                        }
                                        // 移除已处理的帧，保留剩余数据
                                        int remaining = conn_ctx->ws_buffer_len - frame_size;
                                        if (remaining > 0) {
                                            memmove(conn_ctx->ws_buffer, conn_ctx->ws_buffer + frame_size, remaining);
                                        }
                                        conn_ctx->ws_buffer_len = remaining;
                                    } else {
                                        // 帧不完整，等待更多数据
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            break;

        default:
            break;
    }
}

// 主循环
static int main_loop(__rte_unused void *arg) {
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rx;
    static uint64_t pkt_count = 0;

    printf("进入主循环，核心ID: %u\n", rte_lcore_id());

    while (!force_quit) {
        // 批量接收数据包
        nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, MAX_PKT_BURST);

        if (likely(nb_rx > 0)) {
            pkt_count += nb_rx;
            if (pkt_count % 100 == 0) {
                printf("已接收 %lu 个数据包\n", pkt_count);
            }
            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = pkts_burst[i];

                // 快速过滤：只处理发往本机的TCP包
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                // 调试：打印以太网类型
                if (pkt_count <= 10) {
                    printf("DEBUG: 收到包 ether_type=0x%04x\n", rte_be_to_cpu_16(eth->ether_type));
                }

                // 处理ARP包
                if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                    handle_arp_packet(m);
                }
                // 处理IPv4包
                else if (likely(eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
                    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

                    // 调试：打印所有IPv4包信息
                    if (pkt_count <= 20) {
                        printf("DEBUG: 收到IPv4包 proto=%u src_ip=%u.%u.%u.%u dst_ip=%u.%u.%u.%u\n",
                               ip->next_proto_id,
                               (ntohl(ip->src_addr) >> 24) & 0xFF,
                               (ntohl(ip->src_addr) >> 16) & 0xFF,
                               (ntohl(ip->src_addr) >> 8) & 0xFF,
                               ntohl(ip->src_addr) & 0xFF,
                               (ntohl(ip->dst_addr) >> 24) & 0xFF,
                               (ntohl(ip->dst_addr) >> 16) & 0xFF,
                               (ntohl(ip->dst_addr) >> 8) & 0xFF,
                               ntohl(ip->dst_addr) & 0xFF);
                    }

                    if (ip->next_proto_id == IPPROTO_TCP) {
                        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + ((ip->version_ihl & 0x0F) * 4));
                        uint16_t dst_port = rte_be_to_cpu_16(tcp->dst_port);
                        uint16_t src_port = rte_be_to_cpu_16(tcp->src_port);

                        // 只处理发往本机的TCP包
                        if (ip->dst_addr == conn_ctx->local_ip) {
                            process_tcp_packet(m);
                        }
                    }
                }

                rte_pktmbuf_free(m);
            }
        }
    }

    return 0;
}

// 初始化DPDK端口
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        },
        .txmode = {
            .offloads = 0,  // 禁用硬件校验和卸载（AF_PACKET不支持）
        },
    };
    struct rte_eth_dev_info dev_info;
    int ret;

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        return ret;
    }

    // 尝试启用硬件时间戳（DPDK 23.11使用IEEE1588）
    // 注意：不是所有网卡都支持，如果失败会回退到软件时间戳
    printf("网卡RX offload能力: 0x%lx\n", dev_info.rx_offload_capa);

    ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
    if (ret != 0) {
        return ret;
    }

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (ret < 0) {
        return ret;
    }

    ret = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                                 rte_eth_dev_socket_id(port), NULL);
    if (ret < 0) {
        return ret;
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        return ret;
    }

    // 关闭混杂模式（与F-Stack保持一致）
    // rte_eth_promiscuous_enable(port);

    return 0;
}

// 信号处理
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n收到信号 %d，准备退出...\n", signum);
        force_quit = 1;
    }
}

int main(int argc, char **argv) {
    int ret;

    printf("=== 精简版DPDK WebSocket客户端 ===\n");
    printf("目标: 绕过F-Stack降低延迟至 <100μs\n\n");
   
  
   // 打开延迟记录文件
   latency_file = fopen("latency.txt", "w");
   if (latency_file == NULL) {
       printf("Warning: Failed to open latency.txt for writing\n");
   } else {
       printf("End-to-end latency data will be logged to latency.txt\n");
       // 写入表头
       fprintf(latency_file, "trade_id,latency_us\n");
       fflush(latency_file);
   }

    // 初始化DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL初始化失败\n");
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

   // 绑定到CPU核心1
   if (bind_to_cpu_core(1) != 0) {
       printf("Warning: Failed to bind to CPU core 1, continuing anyway...\n");
   }


    // 创建mbuf池
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE * 10,
                                        rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "无法创建mbuf池\n");
    }

    // 分配连接上下文（必须在使用前分配）
    conn_ctx = rte_zmalloc("conn_ctx", sizeof(connection_ctx_t), 0);
    if (conn_ctx == NULL) {
        rte_exit(EXIT_FAILURE, "无法分配连接上下文\n");
    }

    // 初始化端口
    if (port_init(port_id, mbuf_pool) != 0) {
        rte_exit(EXIT_FAILURE, "端口初始化失败\n");
    }

    // 获取MAC地址
    rte_eth_macaddr_get(port_id, &conn_ctx->local_mac);

   // 打印DPDK端口信息
   struct rte_eth_dev_info dev_info;
   rte_eth_dev_info_get(port_id, &dev_info);
   printf("=== DPDK端口信息 ===\n");
   printf("端口ID: %u\n", port_id);
   printf("驱动名称: %s\n", dev_info.driver_name);
   printf("设备名称: %s\n", rte_dev_name(dev_info.device));
   printf("网卡总数: %u\n", rte_eth_dev_count_avail());
   printf("==================\n");

    // 初始化连接参数 (inet_pton返回网络字节序，需要转换)
    struct in_addr addr;
    inet_pton(AF_INET, LOCAL_IP, &addr);
    conn_ctx->local_ip = addr.s_addr;  // 已经是网络字节序
    inet_pton(AF_INET, BINANCE_SERVER_IP, &addr);
    conn_ctx->remote_ip = addr.s_addr;
    inet_pton(AF_INET, GATEWAY_IP, &addr);
    conn_ctx->gateway_ip = addr.s_addr;
    conn_ctx->local_port = LOCAL_PORT;
    conn_ctx->remote_port = BINANCE_SERVER_PORT;

    // 初始化ARP状态
    conn_ctx->arp_resolved = 0;
    conn_ctx->tcp_state = TCP_CLOSED;

    printf("本地MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           conn_ctx->local_mac.addr_bytes[0], conn_ctx->local_mac.addr_bytes[1],
           conn_ctx->local_mac.addr_bytes[2], conn_ctx->local_mac.addr_bytes[3],
           conn_ctx->local_mac.addr_bytes[4], conn_ctx->local_mac.addr_bytes[5]);
    printf("本地IP: %s\n", LOCAL_IP);
    printf("远程IP: %s\n", BINANCE_SERVER_IP);
    printf("网关IP: %s\n", GATEWAY_IP);

    // 初始化TLS
    mbedtls_ssl_init(&conn_ctx->ssl);
    mbedtls_ssl_config_init(&conn_ctx->conf);
    mbedtls_entropy_init(&conn_ctx->entropy);
    mbedtls_ctr_drbg_init(&conn_ctx->ctr_drbg);

    // 初始化随机数生成器
    const char *pers = "dpdk_binance_client";
    if (mbedtls_ctr_drbg_seed(&conn_ctx->ctr_drbg, mbedtls_entropy_func, &conn_ctx->entropy,
                             (const unsigned char *)pers, strlen(pers)) != 0) {
        rte_exit(EXIT_FAILURE, "随机数生成器初始化失败\n");
    }

    // TLS配置（与F-Stack版本相同）
    if (mbedtls_ssl_config_defaults(&conn_ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        rte_exit(EXIT_FAILURE, "SSL配置初始化失败\n");
    }

    mbedtls_ssl_conf_authmode(&conn_ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conn_ctx->conf, mbedtls_ctr_drbg_random, &conn_ctx->ctr_drbg);

    if (mbedtls_ssl_setup(&conn_ctx->ssl, &conn_ctx->conf) != 0) {
        rte_exit(EXIT_FAILURE, "SSL设置失败\n");
    }

    if (mbedtls_ssl_set_hostname(&conn_ctx->ssl, "fstream.binance.com") != 0) {
        rte_exit(EXIT_FAILURE, "设置主机名失败\n");
    }

    mbedtls_ssl_set_bio(&conn_ctx->ssl, conn_ctx, tls_send_callback, tls_recv_callback, NULL);

    // 先发送Gratuitous ARP宣告自己的存在
    printf("发送Gratuitous ARP宣告IP地址...\n");
    send_gratuitous_arp();

    // 然后发送ARP请求获取网关MAC
    printf("发送ARP请求获取网关MAC地址...\n");
    send_arp_request(conn_ctx->gateway_ip);

    // 只在主核心运行（不要多核心，避免竞争）
    main_loop(NULL);

    // 清理资源
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    return 0;
}

// 币安时间戳解析（零拷贝版本）
static inline long long parse_binance_timestamp_fast(const char *data, int len) {
    for (int i = 0; i < len - 4; i++) {
        if (data[i] == '"' && data[i+1] == 'E' && data[i+2] == '"' && data[i+3] == ':') {
            i += 4;
            while (i < len && data[i] == ' ') i++;

            long long result = 0;
            while (i < len && data[i] >= '0' && data[i] <= '9') {
                result = result * 10 + (data[i] - '0');
                i++;
            }
            return result;
        }
    }
    return 0;
}

// 交易ID解析
static inline long long parse_trade_id_fast(const char *data, int len) {
    const char *patterns[] = {"\"a\":", "\"i\":", "\"id\":", "\"t\":"};
    const int pattern_lens[] = {4, 4, 5, 4};

    for (int p = 0; p < 4; p++) {
        for (int i = 0; i < len - pattern_lens[p] - 1; i++) {
            if (memcmp(data + i, patterns[p], pattern_lens[p]) == 0) {
                i += pattern_lens[p];
                while (i < len && (data[i] == ' ' || data[i] == '"')) i++;

                long long result = 0;
                while (i < len && data[i] >= '0' && data[i] <= '9') {
                    result = result * 10 + (data[i] - '0');
                    i++;
                }
                if (result > 0) return result;
            }
        }
    }
    return 0;
}

// 更新延迟统计
static inline void update_latency_stats(double latency_us, double rx_latency_us) {
    latency_stats.total_latency += latency_us;
    latency_stats.count++;

    if (latency_us < latency_stats.min_latency) {
        latency_stats.min_latency = latency_us;
    }
    if (latency_us > latency_stats.max_latency) {
        latency_stats.max_latency = latency_us;
    }

   

    latency_stats.total_rx_latency += rx_latency_us;
    if (rx_latency_us < latency_stats.min_rx_latency) {
        latency_stats.min_rx_latency = rx_latency_us;
    }
    if (rx_latency_us > latency_stats.max_rx_latency) {
        latency_stats.max_rx_latency = rx_latency_us;
    }
}

// 处理币安交易数据
static void process_trade_data(const unsigned char *data, int len, uint64_t hw_timestamp_ns) {
    double process_time = get_timestamp_us();

    // 计算RX延迟（硬件时间戳 -> 应用处理）
    double rx_latency_us = 0.0;
    if (hw_timestamp_ns > 0) {
        double hw_ts_us = (double)hw_timestamp_ns / 1000.0;
        rx_latency_us = process_time - hw_ts_us;
    }

    const char *json_data = (const char *)data;
    char stream_name[50] = "unknown";

    // 提取stream名称和data字段
    const char *data_start = json_data;
    for (int i = 0; i < len - 7; i++) {
        if (memcmp(json_data + i, "\"data\":", 7) == 0) {
            data_start = json_data + i + 7;

            for (int j = 0; j < i - 10; j++) {
                if (memcmp(json_data + j, "\"stream\":\"", 10) == 0) {
                    int name_start = j + 10;
                    int name_len = 0;
                    while (name_start + name_len < len && json_data[name_start + name_len] != '"' && name_len < 49) {
                        stream_name[name_len] = json_data[name_start + name_len];
                        name_len++;
                    }
                    stream_name[name_len] = '\0';
                    break;
                }
            }
            break;
        }
    }

    long long binance_timestamp = parse_binance_timestamp_fast(data_start, len - (data_start - json_data));
    long long trade_id = parse_trade_id_fast(data_start, len - (data_start - json_data));

    double latency_us = 0.0;
    if (likely(binance_timestamp > 0)) {
        latency_us = process_time - ((double)binance_timestamp * 1000.0);
        update_latency_stats(latency_us, rx_latency_us);

       // 批量写入端到端延迟文件
       if (__builtin_expect(latency_file != NULL && latency_us >= 0, 1)) {
           fprintf(latency_file, "%lld,%.1f\n", trade_id, latency_us);
           if (__builtin_expect((latency_stats.count & 1023) == 0, 0)) { // 每1024条消息刷新
               fflush(latency_file);
           }
       }
    }

    // 统计输出（每1000条）
    if (latency_stats.count % 1000 == 0 && latency_stats.count > 0) {
        double avg_latency = latency_stats.total_latency / latency_stats.count;
        double avg_rx_latency = latency_stats.total_rx_latency / latency_stats.count;
        printf("[%d] %s | ID: %lld | E2E: %.1fμs | RX: %.1fμs\n",
               latency_stats.count, stream_name, trade_id, latency_us, rx_latency_us);
        printf("  E2E延迟 - Avg: %.1fμs | Min: %.1fμs | Max: %.1fμs | Jitter: %.1fμs\n",
               avg_latency, latency_stats.min_latency, latency_stats.max_latency,
               latency_stats.max_latency - latency_stats.min_latency);
        printf("  RX延迟  - Avg: %.1fμs | Min: %.1fμs | Max: %.1fμs | Jitter: %.1fμs\n",
               avg_rx_latency, latency_stats.min_rx_latency, latency_stats.max_rx_latency,
               latency_stats.max_rx_latency - latency_stats.min_rx_latency);
    }
}

// WebSocket帧解析
static int parse_websocket_frame(const unsigned char *buffer, int len,
                                unsigned char **payload, int *payload_len, int *opcode) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    int frame_opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int len_field = second_byte & 0x7F;

    int header_len = 2;
    uint64_t actual_len = len_field;

    if (len_field == 126) {
        if (len < 4) return -1;
        actual_len = (buffer[2] << 8) | buffer[3];
        header_len += 2;
    } else if (len_field == 127) {
        if (len < 10) return -1;
        actual_len = ((uint64_t)buffer[6] << 24) | ((uint64_t)buffer[7] << 16) |
                     ((uint64_t)buffer[8] << 8) | (uint64_t)buffer[9];
        header_len += 8;
    }

    if (masked) header_len += 4;

    if (len < header_len + actual_len) {
        return -1;  // 不完整
    }

    if (!fin) {
        return -1;  // 暂不支持分片帧
    }

    *payload = (unsigned char *)buffer + header_len;
    *payload_len = actual_len;
    *opcode = frame_opcode;

    return header_len + actual_len;
}

// 发送WebSocket帧
static int send_websocket_frame(int opcode, const unsigned char *payload, int payload_len) {
    int frame_len = 0;

    g_websocket_frame_send[0] = 0x80 | (opcode & 0x0F);

    if (payload_len < 126) {
        g_websocket_frame_send[1] = 0x80 | payload_len;
        frame_len = 2;
    } else if (payload_len < 65536) {
        g_websocket_frame_send[1] = 0x80 | 126;
        g_websocket_frame_send[2] = (payload_len >> 8) & 0xFF;
        g_websocket_frame_send[3] = payload_len & 0xFF;
        frame_len = 4;
    }

    unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(g_websocket_frame_send + frame_len, mask, 4);
    frame_len += 4;

    for (int i = 0; i < payload_len; i++) {
        g_websocket_frame_send[frame_len + i] = payload[i] ^ mask[i % 4];
    }
    frame_len += payload_len;

    return mbedtls_ssl_write(&conn_ctx->ssl, g_websocket_frame_send, frame_len);
}

static void send_websocket_pong(const unsigned char *payload, int len) {
    send_websocket_frame(WS_OPCODE_PONG, payload, len);
}

