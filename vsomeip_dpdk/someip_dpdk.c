/* DPDK headers */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

/* SOME/IP headers and defines (동일) */
#define VSOMEIP_PORT 30490
#define SERVICE_ID 0x1234
#define INSTANCE_ID 0x5678
#define EVENTGROUP_ID 0x4465
#define SUBSCRIBE_METHOD_ID 0x8100
// SOME/IP SD Message Types
#define SOMEIP_SD_SUBSCRIBE 0x06
#define SOMEIP_SD_SUBSCRIBE_ACK 0x07

// SOME/IP SD Entry Types
#define SD_SUBSCRIBE_EVENTGROUP_ENTRY 0x06
#define SD_SUBSCRIBE_EVENTGROUP_ACK_ENTRY 0x07

// SOMEIP header structure
struct someip_header {
    rte_be16_t service_id;
    rte_be16_t method_id;
    rte_be32_t length;
    rte_be16_t client_id;
    rte_be16_t session_id;
    uint8_t someip_ver;
    uint8_t iface_ver;
    uint8_t msg_type;
    uint8_t ret_code;
} __attribute__((packed));

// SOME/IP SD header structure
struct someip_sd_header {
    uint8_t flags;
    uint8_t reserved[3];
    rte_be32_t length;
} __attribute__((packed));

// SOME/IP SD Entry header
struct someip_sd_entry_header {
    uint8_t type;
    uint8_t index1;
    uint8_t index2;
    uint8_t num_options;
} __attribute__((packed));

// SOME/IP SD Subscribe Entry
struct someip_sd_subscribe_entry {
    rte_be16_t service_id;
    rte_be16_t instance_id;        
    uint8_t major_ver;
    uint8_t ttl[3];
    uint8_t reserved2[2];
    rte_be16_t eventgroup_id;
    rte_be32_t length_options;
} __attribute__((packed));

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

static struct rte_mempool *mbuf_pool = NULL;

// port_init 함수 수정
static int port_init(uint16_t port)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mtu = RTE_ETHER_MAX_LEN,  // max_rx_pkt_len 대신 mtu 사용
        },
    };
    
    if (rte_eth_dev_configure(port, 1, 1, &port_conf) < 0) {
        return -1;
    }
    
    // 나머지 설정은 동일
    if (rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool) < 0) {
        return -1;
    }
    
    if (rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL) < 0) {
        return -1;
    }
    
    if (rte_eth_dev_start(port) < 0) {
        return -1;
    }
    
    return 0;
}

static void process_someip_packet(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    struct someip_header *someip = (struct someip_header *)(udp_hdr + 1);
    struct someip_sd_header *sd = (struct someip_sd_header *)(someip + 1);
    struct someip_sd_entry_header *entry = (struct someip_sd_entry_header *)(sd + 1);
    struct someip_sd_subscribe_entry *sub = (struct someip_sd_subscribe_entry *)(entry + 1);

    // Check if this is a SOME/IP SD Subscribe message
    if (ntohs(udp_hdr->dst_port) != VSOMEIP_PORT ||
        entry->type != SD_SUBSCRIBE_EVENTGROUP_ENTRY ||
        ntohs(sub->service_id) != SERVICE_ID ||
        ntohs(sub->instance_id) != INSTANCE_ID ||
        ntohs(sub->eventgroup_id) != EVENTGROUP_ID) {
        return;
    }
    
    // 이더넷 주소 스왑
    struct rte_ether_addr tmp_mac;
    rte_ether_addr_copy(&eth_hdr->dst_addr, &tmp_mac);             // d_addr -> dst_addr
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);   // s_addr -> src_addr
    rte_ether_addr_copy(&tmp_mac, &eth_hdr->src_addr);             // 수정된 이름 사용
    
    // Swap IP addresses
    uint32_t tmp_ip = ip_hdr->dst_addr;
    ip_hdr->dst_addr = ip_hdr->src_addr;
    ip_hdr->src_addr = tmp_ip;
    
    // Swap UDP ports
    uint16_t tmp_port = udp_hdr->dst_port;
    udp_hdr->dst_port = udp_hdr->src_port;
    udp_hdr->src_port = tmp_port;
    
    // Modify SOMEIP header
    someip->service_id = htons(0xffff);
    someip->method_id = htons(SUBSCRIBE_METHOD_ID);
    someip->msg_type = 0x02;  // Response
    someip->ret_code = 0x00;  // OK
    someip->someip_ver = 0x01;
    someip->iface_ver = 0x01;
    
    // Modify SD header
    sd->flags = 0xc0;
    memset(sd->reserved, 0, sizeof(sd->reserved));
    
    // Modify entry header
    entry->type = SD_SUBSCRIBE_EVENTGROUP_ACK_ENTRY;
    entry->index1 = 0;
    entry->index2 = 0;
    entry->num_options = 0;
    
    // Modify subscribe entry
    sub->major_ver = 0x01;
    sub->ttl[0] = 0x00;
    sub->ttl[1] = 0x00;
    sub->ttl[2] = 0x03;
    memset(sub->reserved2, 0, sizeof(sub->reserved2));
    sub->length_options = 0;
    
    // Calculate lengths
    uint32_t someip_payload_len = sizeof(struct someip_sd_header) +
                                 sizeof(struct someip_sd_entry_header) +
                                 sizeof(struct someip_sd_subscribe_entry);
    
    someip->length = htonl(someip_payload_len + sizeof(struct someip_header) - 8);
    sd->length = htonl(someip_payload_len - sizeof(struct someip_sd_header));
    
    // Update IP length
    ip_hdr->total_length = htons(sizeof(struct rte_ipv4_hdr) +
                                sizeof(struct rte_udp_hdr) +
                                sizeof(struct someip_header) +
                                someip_payload_len);
                                
    // Update UDP length
    udp_hdr->dgram_len = htons(sizeof(struct rte_udp_hdr) +
                              sizeof(struct someip_header) +
                              someip_payload_len);
                              
    // Recalculate IP checksum
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
    
    // Recalculate UDP checksum (optional)
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
}

int main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        return -1;
    }
    
    // Create mbuf pool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        
    if (mbuf_pool == NULL) {
        return -1;
    }
    
    // Initialize port
    uint16_t portid = 0;  // Use first port
    if (port_init(portid) != 0) {
        return -1;
    }
    
    printf("Starting packet processing on port %u...\n", portid);
    
    while (1) {
        struct rte_mbuf *bufs[32];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, 32);
        
        if (nb_rx == 0)
            continue;
            
        for (uint16_t i = 0; i < nb_rx; i++) {
            process_someip_packet(bufs[i]);
            rte_eth_tx_burst(portid, 0, &bufs[i], 1);
        }
    }
    
    return 0;
}
