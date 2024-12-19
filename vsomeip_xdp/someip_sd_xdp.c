// UAPI Headers
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>     // IPPROTO_UDP를 위해 추가
#include <linux/types.h>  // 기본 타입 정의를 위해 추가

// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// License definition required for BPF programs
#define LICENSE "GPL"

// VSOMEIP Port definition
#define VSOMEIP_PORT 30490

// Service specific defines
#define SERVICE_ID 0x1234
#define INSTANCE_ID 0x5678
#define EVENTGROUP_ID 0x4465

// SOME/IP SD Message Types
#define SOMEIP_SD_SUBSCRIBE 0x06
#define SOMEIP_SD_SUBSCRIBE_ACK 0x07

// SOME/IP SD Entry Types
#define SD_SUBSCRIBE_EVENTGROUP_ENTRY 0x06
#define SD_SUBSCRIBE_EVENTGROUP_ACK_ENTRY 0x07

// Packet size definitions
#define ETH_HLEN 14
#define IP_HLEN 20
#define UDP_HLEN 8

// SOMEIP header structure
struct someip_header {
    __be16 service_id;
    __be16 method_id;
    __be32 length;
    __be16 client_id;
    __be16 session_id;
    __u8 someip_ver;
    __u8 iface_ver;
    __u8 msg_type;
    __u8 ret_code;
} __attribute__((packed));

// SOME/IP SD header structure
struct someip_sd_header {
    __u8 flags;
    __u8 reserved[3];
    __be32 length;
} __attribute__((packed));

// SOME/IP SD Entry header
struct someip_sd_entry_header {
    __u8 type;
    __u8 index1;
    __u8 index2;
    __u8 num_options;
} __attribute__((packed));

// SOME/IP SD Subscribe Entry
struct someip_sd_subscribe_entry {
    __be16 service_id;
    __be16 instance_id;        
    __u8 major_ver;
    __u8 ttl[3];
    __u8 reserved2[2];
    __be16 eventgroup_id;
    __be32 length_options;
} __attribute__((packed));

// IP 체크섬 계산을 위한 헬퍼 함수
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 sum = csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline __u32 csum_add(__u32 addend, __u32 csum)
{
    return csum + addend;
}

static __always_inline void update_iph_checksum(struct iphdr *iph)
{
    __u32 csum = 0;
    __u16 *next_iph_u16 = (__u16 *)iph;
    
    iph->check = 0;
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        csum = csum_add((__u32)next_iph_u16[i], csum);
    }
    
    iph->check = csum_fold_helper(csum);
}

// Helper function to swap MAC addresses
static __always_inline void swap_mac(unsigned char *dst, unsigned char *src) {
    unsigned char tmp;
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp = dst[i];
        dst[i] = src[i];
        src[i] = tmp;
    }
}

// Helper function to swap IP addresses
static __always_inline void swap_ip(__be32 *dst, __be32 *src) {
    __be32 tmp = *dst;
    *dst = *src;
    *src = tmp;
}

SEC("xdp")
int someip_subscribe_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Bounds checking with correct pointer arithmetic
    void *ptr = data;
    struct ethhdr *eth = ptr;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ptr += sizeof(struct ethhdr);
    struct iphdr *iph = ptr;
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;
        
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    ptr += sizeof(struct iphdr);
    struct udphdr *udph = ptr;
    if ((void*)(udph + 1) > data_end)
        return XDP_PASS;
        
    if (bpf_ntohs(udph->dest) != VSOMEIP_PORT)
        return XDP_PASS;

    ptr += sizeof(struct udphdr);
    struct someip_header *someip = ptr;
    if ((void*)(someip + 1) > data_end)
        return XDP_PASS;

    ptr += sizeof(struct someip_header);
    struct someip_sd_header *sd = ptr;
    if ((void*)(sd + 1) > data_end)
        return XDP_PASS;

    ptr += sizeof(struct someip_sd_header);
    struct someip_sd_entry_header *entry = ptr;
    if ((void*)(entry + 1) > data_end)
        return XDP_PASS;

    if (entry->type != SD_SUBSCRIBE_EVENTGROUP_ENTRY)
        return XDP_PASS;

    ptr += sizeof(struct someip_sd_entry_header);
    struct someip_sd_subscribe_entry *sub = ptr;
    if ((void*)(sub + 1) > data_end)
        return XDP_PASS;
    
    if (bpf_ntohs(sub->service_id) != SERVICE_ID ||
        bpf_ntohs(sub->instance_id) != INSTANCE_ID ||
        bpf_ntohs(sub->eventgroup_id) != EVENTGROUP_ID)
        return XDP_PASS;

    // 전체 패킷 길이 계산
    __u32 total_length = sizeof(struct ethhdr) + 
                        sizeof(struct iphdr) + 
                        sizeof(struct udphdr) + 
                        sizeof(struct someip_header) +
                        sizeof(struct someip_sd_header) + 
                        sizeof(struct someip_sd_entry_header) +
                        sizeof(struct someip_sd_subscribe_entry);
                        
    // Modify ethernet header
    swap_mac(eth->h_dest, eth->h_source);
    
    // Modify IP header
    swap_ip(&iph->daddr, &iph->saddr);
    iph->tot_len = bpf_htons(total_length - sizeof(struct ethhdr));  // IP 패킷 전체 길이 설정
    update_iph_checksum(iph);  // 체크섬 계산

    // Modify UDP ports
    __be16 tmp_port = udph->dest;
    udph->dest = udph->source;
    udph->source = tmp_port;
    udph->len = bpf_htons(total_length - sizeof(struct ethhdr) - sizeof(struct iphdr));  // UDP 길이 설정
    udph->check = 0;  // Let the NIC calculate UDP checksum

    // Modify SOMEIP header
    someip->service_id = bpf_htons(0xffff);
    someip->method_id = bpf_htons(0x8100);
    someip->client_id = someip->client_id;
    someip->session_id = someip->session_id;
    someip->someip_ver = 0x01;
    someip->iface_ver = 0x01;
    someip->msg_type = 0x02;  // Response
    someip->ret_code = 0x00;  // OK

    // Modify SD header
    sd->flags = 0xc0;  // Reboot flag + Unicast flag
    sd->reserved[0] = 0;
    sd->reserved[1] = 0;
    sd->reserved[2] = 0;
    
    // Modify Entry header
    entry->type = SD_SUBSCRIBE_EVENTGROUP_ACK_ENTRY;
    entry->index1 = 0;
    entry->index2 = 0;
    entry->num_options = 0;

    // Modify Subscribe Entry
    sub->service_id = bpf_htons(SERVICE_ID);
    sub->instance_id = bpf_htons(INSTANCE_ID);
    sub->major_ver = 0x00;
    sub->ttl[0] = 0x00;
    sub->ttl[1] = 0x00;
    sub->ttl[2] = 0x03;
    sub->reserved2[0] = 0;
    sub->reserved2[1] = 0;
    sub->eventgroup_id = bpf_htons(EVENTGROUP_ID);
    sub->length_options = 0;

    // Calculate lengths
    __u32 someip_payload_length = sizeof(struct someip_sd_header) +
                                 sizeof(struct someip_sd_entry_header) +
                                 sizeof(struct someip_sd_subscribe_entry);
    
    someip->length = bpf_htonl(sizeof(struct someip_header) + someip_payload_length - 8);
    sd->length = bpf_htonl(someip_payload_length - sizeof(struct someip_sd_header) - 4);

        // XDP의 패킷 길이를 조정
    int result = bpf_xdp_adjust_tail(ctx, total_length - (data_end - data));
    if (result != 0)
        return XDP_DROP;  // 길이 조정 실패시 패킷 드롭

    return XDP_TX;
}


char _license[] SEC("license") = LICENSE;
