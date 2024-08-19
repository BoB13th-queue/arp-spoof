#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t version_ihl_;       // 4-bit version and 4-bit header length
    uint8_t tos_;               // Type of service
    uint16_t total_length_;     // Total length of the packet
    uint16_t id_;               // Identification
    uint16_t flags_offset_;     // 3-bit flags and 13-bit fragment offset
    uint8_t ttl_;               // Time to live
    uint8_t protocol_;          // Protocol
    uint16_t checksum_;         // Header checksum
    Ip src_ip_;                 // Source IP address
    Ip dst_ip_;                 // Destination IP address

    uint8_t version_ihl() { return version_ihl_; } 
    uint8_t tos() { return tos_; } 
    uint16_t total_length() { return ntohs(total_length_); } 
    uint16_t id() { return ntohs(id_); } 
    uint16_t flags_offset() { return ntohs(flags_offset_); } 
    uint8_t ttl() { return ttl_; } 
    uint8_t protocol() { return protocol_; } 
    uint16_t checksum() { return ntohs(checksum_); }
    Ip src_ip() { return ntohl(src_ip_); } 
    Ip dst_ip() { return ntohl(dst_ip_); } 

    // Protocol (protocol_)
    enum : uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17
    };
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)