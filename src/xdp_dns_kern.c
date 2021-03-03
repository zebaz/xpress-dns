/*
Xpress DNS: Experimental XDP DNS responder
Copyright (C) 2020 Bas Schalbroeck <schalbroeck@gmail.com>

SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330
*/
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <string.h>
#include "common.h"
//bpf_elf.h is part of iproute2
#include <bpf_elf.h>

#define DEFAULT_ACTION XDP_PASS

//Hash table for DNS A Records
//Key is a dns_query, value is the associated IPv4 address
struct bpf_elf_map SEC("maps") xdns_a_records = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct dns_query),
    .size_value = sizeof(struct a_record),
    .max_elem = 65536,
    .pinning = 2, //PIN_GLOBAL_NS
};

static inline int match_a_records(struct xdp_md *ctx, struct dns_query *q, struct a_record *a);
static inline int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q);
static inline void modify_packet_with_response(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct a_record *a);
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location);
static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac);

SEC("prog")
int xdp_dns(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;

    //Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return DEFAULT_ACTION;
    }

    struct ethhdr *eth = data;

    //Ignore packet if ethernet protocol is not IP-based
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return DEFAULT_ACTION;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp;
        //Boundary check for UDP
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        {
            return DEFAULT_ACTION;
        }

        udp = data + sizeof(*eth) + sizeof(*ip);

        //Check if dest port equals 53
        if (udp->dest == bpf_htons(53))
        {
            #ifdef DEBUG
            bpf_printk("Packet dest port 53");
            bpf_printk("Data pointer starts at %u", data);
            #endif

            //Boundary check for min DNS header
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end)
            {
                return DEFAULT_ACTION;
            }

            struct dns_hdr *dns = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

            //Check if header contains a standard query
            if (dns->qr == 0 && dns->opcode == 0)
            {
                #ifdef DEBUG
                bpf_printk("DNS query transaction id %u", bpf_ntohs(dns->transaction_id));
                #endif

                //Get a pointer to the start of the dns queries
                void *query_start = (void *)dns + sizeof(struct dns_hdr);

                //We will only be parsing a single query for now
                struct dns_query q;
                int query_length = 0;
                query_length = parse_query(ctx, query_start, &q);
                if (query_length < 1)
                {
                    return DEFAULT_ACTION;
                }

                //Check if query matches a record in our hash table
                struct a_record a_record;
                int res = match_a_records(ctx, &q, &a_record);

                //If query matches...
                if (res == 0)
                {
                    //Modify packet with DNS response. Packet length will be adjusted accordingly.
                    modify_packet_with_response(ctx, dns, query_length, &a_record);

                    //Because we adjusted packet length, mem addresses might be changed.
                    //Reinit pointers, as verifier will complain otherwise.
                    data = (void *)(unsigned long)ctx->data;
                    data_end = (void *)(unsigned long)ctx->data_end;
                    eth = data;
                    ip = data + sizeof(struct ethhdr);
                    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

                    //Do a new boundary check
                    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
                    {
                        #ifdef DEBUG
                        bpf_printk("Error: Boundary exceeded");
                        #endif
                        return DEFAULT_ACTION;
                    }

                    //Swap eth macs
                    swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                    //Swap src/dst IP
                    uint32_t src_ip = ip->saddr;
                    ip->saddr = ip->daddr;
                    ip->daddr = src_ip;

                    //Set UDP checksum to zero
                    udp->check = 0;

                    //Swap udp src/dst ports
                    uint16_t tmp_src = udp->source;
                    udp->source = udp->dest;
                    udp->dest = tmp_src;

                    //Recalculate IP checksum
                    update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                    #ifdef DEBUG
                    bpf_printk("XDP_TX");
                    #endif

                    //Emit modified packet
                    return XDP_TX;
                }
            }
        }
    }

    return DEFAULT_ACTION;
}

static inline int match_a_records(struct xdp_md *ctx, struct dns_query *q, struct a_record *a)
{
    #ifdef DEBUG
    bpf_printk("DNS record type: %i", q->record_type);
    bpf_printk("DNS class: %i", q->class);
    bpf_printk("DNS name: %s", q->name);
    #endif

    struct a_record *record;
    record = bpf_map_lookup_elem(&xdns_a_records, q);

    //If record pointer is not zero..
    if (record > 0)
    {
        #ifdef DEBUG
        bpf_printk("DNS query matched");
        #endif
        a->ip_addr = record->ip_addr;
        a->ttl = record->ttl;

        return 0;
    }

    return -1;
}

//Parse query and return query length
static inline int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q)
{
    void *data_end = (void *)(long)ctx->data_end;

    #ifdef DEBUG
    bpf_printk("Parsing query");
    #endif

    uint16_t i;
    void *cursor = query_start;
    int namepos = 0;

    //Fill dns_query.name with zero bytes
    //Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
    memset(&q->name[0], 0, sizeof(q->name));
    //Fill record_type and class with default values to satisfy verifier
    q->record_type = 0;
    q->class = 0;

    //We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
    //We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
    for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
    {

        //Boundary check
        //TODO: Boundary check here requires a +1 to work, find out why!
        if (cursor + 1 > data_end)
        {
            #ifdef DEBUG
            bpf_printk("Error: boundary exceeded while parsing DNS query name");
            #endif
            break;
        }

        /*
        #ifdef DEBUG
        bpf_printk("Cursor contents is %u\n", *(char *)cursor);
        #endif
        */

        //If separator is zero we've reached the end of the domain query
        if (*(char *)(cursor) == 0)
        {

            //We've reached the end of the query name.
            //This will be followed by 2x 2 bytes: the dns type and dns class.
            if (cursor + 5 > data_end)
            {
                #ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
                #endif
            }
            else
            {
                q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
                q->class = bpf_htons(*(uint16_t *)(cursor + 3));
            }

            //Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
            return namepos + 1 + 2 + 2;
        }

        //Read and fill data into struct
        q->name[namepos] = *(char *)(cursor);
        namepos++;
        cursor++;
    }

    return -1;
}

static inline void modify_packet_with_response(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct a_record *a)
{
    void *data_end = (void *)(long)ctx->data_end;

    //Set query response
    dns_hdr->qr = 1;
    //Set truncated to 0
    //dns_hdr->tc = 0;
    //Set authorative to zero
    //dns_hdr->aa = 0;
    //Recursion available
    dns_hdr->ra = 1;
    //One answer
    dns_hdr->ans_count = bpf_htons(1);

    //Start our response [query_length] bytes beyond the header
    void *answer_start = (void *)dns_hdr + sizeof(*dns_hdr) + query_length;
    //Formulate a DNS response. Currently defaults to hardcoded query pointer + type a + class in + ttl + 4 bytes as reply.
    struct dns_response response;
    response.query_pointer = 0x0cc0; //net order
    response.record_type = 0x0100; //net order
    response.class = 0x0100; //net order
    response.ttl = bpf_htonl(a->ttl);
    response.data_length = bpf_htons((uint16_t)sizeof(a->ip_addr));

    //Determine increment of tail size of a default DNS response and one IPv4 address (in_addr)
    int tailadjust = answer_start + sizeof(response) + sizeof(a->ip_addr) - data_end;
    #ifdef DEBUG
    bpf_printk("Query length is %i", query_length);
    bpf_printk("Answer start at %u", answer_start);
    bpf_printk("Adjust tail with %i bytes", tailadjust);
    bpf_printk("Current data_end: %u", data_end);
    #endif

    if (bpf_xdp_adjust_tail(ctx, tailadjust))
    {
        #ifdef DEBUG
        bpf_printk("Adjust tail fail");
        #endif
    }
    else
    {
        //Reset data_end and data pointers
        void *data = (void *)(unsigned long)ctx->data;
        data_end = (void *)(unsigned long)ctx->data_end;
        #ifdef DEBUG
        bpf_printk("New data_end %u", data_end);
        #endif

        //Boundary check
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
                sizeof(struct dns_hdr) + query_length + sizeof(response) + sizeof(a->ip_addr) <=
            data_end)
        {
            //Copy DNS response
            __builtin_memcpy(data + sizeof(struct ethhdr) +
                                 sizeof(struct iphdr) +
                                 sizeof(struct udphdr) +
                                 sizeof(struct dns_hdr) +
                                 query_length,
                             &response, sizeof(response));

            //Copy IP address from A record
            __builtin_memcpy(data + sizeof(struct ethhdr) +
                                 sizeof(struct iphdr) +
                                 sizeof(struct udphdr) +
                                 sizeof(struct dns_hdr) +
                                 query_length +
                                 sizeof(response),
                             &a->ip_addr, sizeof(a->ip_addr));

            //Adjust UDP length and IP length
            uint16_t iplen = (data_end - data) - sizeof(struct ethhdr);
            uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
            struct iphdr *ip = data + sizeof(struct ethhdr);
            struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

            ip->tot_len = bpf_htons(iplen);
            udp->len = bpf_htons(udplen);
        }
    }
}

//Update IP checksum for IP (or ICMP) header, as specified in RFC 1071
//To support both IP and ICMP updating of checksum, we pass the checksum_location,
//which indicates where in the header the checksum is located. Here 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
    uint32_t accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        uint16_t val;
        //If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            //Else we load two bytes of data into val
            val = *(uint16_t *)(data + i);
        }
        accumulator += val;
    }

    //Add 16 bits overflow back to accumulator (if necessary)
    uint16_t overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    //If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    //Invert bits and set the checksum at checksum_location
    uint16_t chk = accumulator ^ 0xFFFF;

    #ifdef DEBUG
    bpf_printk("Checksum: %u", chk);
    #endif

    *checksum_location = chk;
}

static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        uint8_t tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
    }
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
