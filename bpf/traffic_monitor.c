#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct traffic_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
} __attribute__((packed));

struct traffic_value {
    __u64 bytes;
    __u64 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct traffic_key);
    __type(value, struct traffic_value);
} traffic_map SEC(".maps");

SEC("xdp")
int traffic_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u16 pkt_size = data_end - data;
    
    struct traffic_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol
    };
    
    struct traffic_value new_value = {
        .bytes = pkt_size,
        .packets = 1
    };

    struct traffic_value *value = bpf_map_lookup_elem(&traffic_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->bytes, pkt_size);
        __sync_fetch_and_add(&value->packets, 1);
    } else {
        bpf_map_update_elem(&traffic_map, &key, &new_value, BPF_ANY);
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";