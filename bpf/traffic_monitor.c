#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct traffic_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
    __u32 ifindex;
    __u32 src_port;
    __u32 dst_port;
} __attribute__((packed));

struct traffic_value {
    __u64 bytes;
    __u64 packets;
    __u64 last_update;
    __u64 processed; 
    __u64 init;
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
    
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS; 
    }

    struct ethhdr *eth = data;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
        
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_port = 0;
    __u32 dst_port = 0;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    void *transport_header = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;
        if (tcp + 1 > (struct tcphdr *)data_end)
            return XDP_PASS;
            
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    }

    __u16 pkt_size = data_end - data;
    
    if (ctx->ingress_ifindex == 0) {
        return XDP_PASS;
    }
    
    struct traffic_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
        .ifindex = ctx->ingress_ifindex,
        .src_port = src_port,
        .dst_port = dst_port,
    };
    
    __u64 current_time = bpf_ktime_get_ns();
    struct traffic_value new_value = {
        .bytes = pkt_size,
        .packets = 1,
        .last_update = current_time,
        .processed = 0,
        .init = 0,
    };

    struct traffic_value *value = bpf_map_lookup_elem(&traffic_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->bytes, pkt_size);
        __sync_fetch_and_add(&value->packets, 1);
        // value->src_port = src_port;
        // value->dst_port = dst_port;
        value->last_update = current_time;
        value->processed = 0;
    } else {
        bpf_map_update_elem(&traffic_map, &key, &new_value, BPF_ANY);
        value = bpf_map_lookup_elem(&traffic_map, &key);
        value->init = 1;
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";