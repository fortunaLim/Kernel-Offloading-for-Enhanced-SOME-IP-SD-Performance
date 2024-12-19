#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#define VSOMEIP_PORT 30490

// Service specific defines
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("SOMEIP Subscribe Handler for Specific Service");

static struct nf_hook_ops *nf_hook_ops = NULL;

// SOMEIP 헤더 구조체
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

// SOME/IP SD 헤더 구조체
struct someip_sd_header {
    __u8 flags;
    __u8 reserved[3];
    __be32 length;
} __attribute__((packed));

// SOME/IP SD Entry 헤더
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


static int send_someip_sd_ack(struct net *net, struct sk_buff *ack_skb)
{
    struct net_device *dev;
    int ret;

    // 특정 인터페이스 선택 (ens33)
    dev = dev_get_by_name(&init_net, "ens33");
    if (!dev) {
        printk(KERN_ERR "Network device ens33 not found\n");
        return -ENODEV;
    }

    // 스키 버퍼에 디바이스 설정
    ack_skb->dev = dev;

    // 패킷 전송
    ret = dev_queue_xmit(ack_skb);
    
    // 디바이스 참조 카운트 감소
    dev_put(dev);

    if (ret < 0) {
        printk(KERN_ERR "Packet transmission failed: %d\n", ret);
        return ret;
    }

    return 0;
}

// ACK 패킷 생성 함수
static struct sk_buff *create_someip_sd_ack(struct sk_buff *skb, struct iphdr *iph, 
                                          struct udphdr *udph, struct someip_header *req_someip,
                                          struct someip_sd_subscribe_entry *sub_entry)
{
    struct net_device *dev;
    struct sk_buff *ack_skb;
    struct ethhdr *eth;
    struct iphdr *ack_iph;
    struct udphdr *ack_udph;
    struct someip_header *ack_someip;
    struct someip_sd_header *ack_sd;
    struct someip_sd_entry_header *ack_entry_hdr;
    struct someip_sd_subscribe_entry *ack_entry;
    unsigned int total_len;
    
    // 입력 패킷의 디바이스 가져오기
    dev = skb->dev;
    if (!dev) {
        printk(KERN_ERR "Cannot find network device\n");
        return NULL;
    }

    // 전체 패킷 길이 계산 (이더넷 헤더 포함)
    total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + 
                sizeof(struct udphdr) + sizeof(struct someip_header) + 
                sizeof(struct someip_sd_header) + 
                sizeof(struct someip_sd_entry_header) +
                sizeof(struct someip_sd_subscribe_entry);

    // SKB 할당
    ack_skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
    if (!ack_skb) {
        return NULL;
    }

    skb_reserve(ack_skb, NET_IP_ALIGN);
    skb_reset_mac_header(ack_skb);
    skb_put(ack_skb, total_len);

    // 이더넷 헤더 설정
    eth = (struct ethhdr *)skb_mac_header(ack_skb);
    // 원본 패킷의 MAC 주소 스왑
    memcpy(eth->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // IP 헤더 설정
    skb_set_network_header(ack_skb, sizeof(struct ethhdr));
    ack_iph = (struct iphdr *)skb_network_header(ack_skb);
    ack_iph->version = 4;
    ack_iph->ihl = 5;
    ack_iph->tos = 0;
    ack_iph->tot_len = htons(total_len - sizeof(struct ethhdr));
    ack_iph->id = get_random_u32();
    ack_iph->frag_off = 0;
    ack_iph->ttl = 64;
    ack_iph->protocol = IPPROTO_UDP;
    ack_iph->check = 0;
    ack_iph->saddr = iph->daddr;
    ack_iph->daddr = iph->saddr;

    // UDP 헤더 설정
    skb_set_transport_header(ack_skb, sizeof(struct ethhdr) + sizeof(struct iphdr));
    ack_udph = (struct udphdr *)skb_transport_header(ack_skb);
    ack_udph->source = udph->dest;
    ack_udph->dest = udph->source;
    ack_udph->len = htons(total_len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    ack_udph->check = 0;

    // SOMEIP 및 SD 헤더 설정 (이전과 동일)
    ack_someip = (struct someip_header *)(skb_transport_header(ack_skb) + sizeof(struct udphdr));
    ack_someip->service_id = req_someip->service_id;
    ack_someip->method_id = req_someip->method_id;
    ack_someip->length = cpu_to_be32(total_len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr) - 8);
    ack_someip->client_id = req_someip->client_id;
    ack_someip->session_id = req_someip->session_id;
    ack_someip->someip_ver = req_someip->someip_ver;
    ack_someip->iface_ver = req_someip->iface_ver;
    ack_someip->msg_type = 0x02;
    ack_someip->ret_code = 0x00;

    // SOME/IP SD 헤더 설정
    ack_sd = (struct someip_sd_header *)((char *)ack_someip + sizeof(struct someip_header));
    ack_sd->flags = 0xc0;
    memset(ack_sd->reserved, 0, sizeof(ack_sd->reserved));
    ack_sd->length = cpu_to_be32(total_len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr) - sizeof(struct someip_header) - 12);

    // SD Entry 헤더 설정
    ack_entry_hdr = (struct someip_sd_entry_header *)((char *)ack_sd + sizeof(struct someip_sd_header));
    ack_entry_hdr->type = SD_SUBSCRIBE_EVENTGROUP_ACK_ENTRY;
    ack_entry_hdr->index1 = 0;
    ack_entry_hdr->index2 = 0;
    ack_entry_hdr->num_options = 0;

    // Subscribe Entry 설정
    ack_entry = (struct someip_sd_subscribe_entry *)((char *)ack_entry_hdr + sizeof(struct someip_sd_entry_header));
    ack_entry->service_id = sub_entry->service_id;
    ack_entry->instance_id = sub_entry->instance_id;
    ack_entry->major_ver = sub_entry->major_ver;
    //memcpy(ack_entry->ttl, sub_entry->ttl, sizeof(ack_entry->ttl));
    ack_entry->ttl[2] = 0x03;
    memset(ack_entry->reserved2, 0, sizeof(ack_entry->reserved2));
    ack_entry->eventgroup_id = sub_entry->eventgroup_id;
    ack_entry->length_options = 0;
    
    // IP 체크섬 계산
    ack_iph->check = ip_fast_csum((unsigned char *)ack_iph, ack_iph->ihl);
    
    // 스키 버퍼 메타데이터 설정
    ack_skb->dev = dev;
    skb_set_network_header(ack_skb, 0);
    ack_skb->protocol = htons(ETH_P_IP);
    ack_skb->ip_summed = CHECKSUM_NONE;

    dev_put(dev);

    return ack_skb;
}


// Netfilter 훅 함수
static unsigned int someip_hook_fn(void *priv, struct sk_buff *skb, 
                                 const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct someip_header *someip_hdr;
    struct someip_sd_header *sd_hdr;
    struct someip_sd_entry_header *entry_hdr;
    struct someip_sd_subscribe_entry *sub_entry;
    struct sk_buff *ack_skb;
    int ret;
    
    if (!skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;
    
    udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));
    if (ntohs(udph->dest) != VSOMEIP_PORT)
        return NF_ACCEPT;
    
    someip_hdr = (struct someip_header *)((char *)udph + sizeof(struct udphdr));
    
    // SOME/IP SD 헤더 체크
    sd_hdr = (struct someip_sd_header *)((char *)someip_hdr + sizeof(struct someip_header));
    entry_hdr = (struct someip_sd_entry_header *)((char *)sd_hdr + sizeof(struct someip_sd_header));
    
    if (entry_hdr->type != SD_SUBSCRIBE_EVENTGROUP_ENTRY)
        return NF_ACCEPT;

    // Subscribe Entry 체크
    sub_entry = (struct someip_sd_subscribe_entry *)((char *)entry_hdr + sizeof(struct someip_sd_entry_header));
    
    
    printk(KERN_INFO "SOMEIP-SD Subscribe detected for Service: 0x%04x, Instance: 0x%04x, Eventgroup: 0x%04x\n",
           ntohs(sub_entry->service_id), ntohs(sub_entry->instance_id), ntohs(sub_entry->eventgroup_id));
    
    if (ntohs(sub_entry->service_id) != SERVICE_ID ||
        ntohs(sub_entry->instance_id) != INSTANCE_ID ||
        ntohs(sub_entry->eventgroup_id) != EVENTGROUP_ID)
        return NF_ACCEPT;
    
    printk(KERN_INFO "SOMEIP-SD Subscribe detected for Service: 0x%04x, Instance: 0x%04x, Eventgroup: 0x%04x\n",
           SERVICE_ID, INSTANCE_ID, EVENTGROUP_ID);
    
    // ACK 패킷 생성
    ack_skb = create_someip_sd_ack(skb, iph, udph, someip_hdr, sub_entry);
    if (!ack_skb) {
        printk(KERN_ERR "Failed to create ACK packet\n");
        return NF_ACCEPT;
    }

    // 패킷 전송 시도
    ret = send_someip_sd_ack(state->net, ack_skb);
    
    if (ret < 0) {
        printk(KERN_ERR "Packet send failed. Error: %d\n", ret);
        kfree_skb(ack_skb);
        return NF_ACCEPT;
    }

    printk(KERN_INFO "SOMEIP-SD Subscribe ACK sent successfully\n");
    return NF_DROP;
}

// 모듈 초기화 함수
static int __init someip_handler_init(void)
{
    nf_hook_ops = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!nf_hook_ops)
        return -ENOMEM;
    
    // Netfilter 훅 설정
    nf_hook_ops->hook = someip_hook_fn;
    nf_hook_ops->hooknum = NF_INET_PRE_ROUTING;
    nf_hook_ops->pf = PF_INET;
    nf_hook_ops->priority = NF_IP_PRI_FIRST;
    
    printk(KERN_INFO "SOMEIP-SD Subscribe handler initialized for Service: 0x%04x, Instance: 0x%04x, Eventgroup: 0x%04x\n",
           SERVICE_ID, INSTANCE_ID, EVENTGROUP_ID);
    
    return nf_register_net_hook(&init_net, nf_hook_ops);
}

// 모듈 정리 함수
static void __exit someip_handler_exit(void)
{
    if (nf_hook_ops) {
        nf_unregister_net_hook(&init_net, nf_hook_ops);
        kfree(nf_hook_ops);
    }
    printk(KERN_INFO "SOMEIP-SD Subscribe handler unloaded\n");
}

module_init(someip_handler_init);
module_exit(someip_handler_exit);
