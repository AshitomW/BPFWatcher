#ifndef NETWORK_TYPES_H
#define NETWORK_TYPES_H


/* Network Protocol Definitions*/


#include <cstdint>
#include <stdint.h>
#include "platform.h"




/* Ethernet header*/
#define ETH_ALEN 6
#define ETH_HLEN 14

#define ETH_P_IP 0x0800 // IPV4
#define ETH_P_IPV6 0x86DD // IPV6
#define ETH_P_ARP 0x0806 // ARP
#define ETH_P_8021Q 0x8100 // VLAN


struct eth_header{
  uint8_t dest[ETH_ALEN];
  uint8_t src[ETH_ALEN];
  uint16_t proto;
} PACKED;


// IPv4 Header

struct ipv4_header{
  uint8_t version_ihl; // Version (4 bits) + IHL (4 bits)
  uint8_t tos; // Type of service
  uint16_t total_length; // Total Length
  uint16_t id; // Identification
  uint16_t frag_off; // Fragmentation Offset
  uint8_t ttl; // Time to live
  uint8_t protocol; // Protocol
  uint16_t checksum; // Header Checksum
  uint32_t src_addr; // Source address
  uint32_t dst_addr; // Destination Address
} PACKED;


#define IPV4_GET_VERSION(hdr) (((hdr)->version_ihl >> 4) & 0x0F)
#define IPV4_GET_IHL(hdr) ((hdr)->version_ihl & 0x0F)
#define IPV4_HDR_LEN(hdr) (IPV4_GET_IHL(hdr) * 4)


// IPv6 Header

struct ipv6_header {
  uint32_t version_tc_flow;
  uint16_t payload_length; 
  uint8_t next_header;
  uint8_t hop_limit;
  uint8_t src_address[16]; 
  uint8_t dst_address[16];
}PACKED;


#define IPV6_GET_VERSION(hdr) ((ntohl((hdr)->version_tc_flow) >> 28) &0x0F)


// Protocol Numbers

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTOICMPv6 58


// TCP Header


struct tcp_header{
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t data_offset; // Data offset (4bits) + reserved;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
}PACKED;

#define TCP_GET_DATA_OFFSET(hdr) (((hdr)->data_offset >> 4) & 0x0F)
#define TCP_HDR_LEN(hdr) (TCP_GET_DATA_OFFSET(hdr) * 4)




// TCP FLAGS


#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02 
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80




// UDP Header


struct udp_header{
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
} PACKED;



// ICMP Header


struct icmp_header{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t rest; // Varies by type 
}PACKED; 

// ICMP Types

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_DEST_UNREACH 3 
#define ICMP_TIME_EXCEEDED 11 


// ARP Header 

struct arp_header{
  uint16_t hw_tpe;
  uint16_t proto_type;
  uint8_t hw_len;
  uint8_t proto_len;
  uint16_t opcode;
  uint8_t sender_hw[ETH_ALEN];
  uint32_t sender_ip;
  uint8_t target_hw[ETH_ALEN];
  uint32_t target_ip;
} PACKED;



#define ARP_REQUEST 1
#define ARP_REPLY 2


// Connection tuple for tracking flows

struct flow_key{
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint8_t protocol;
  uint8_t pad[3];
} PACKED ALIGNED(8);


// Flow key for IPv6 


struct flow_key_v6 {
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t pad[3];
}PACKED ALIGNED(8);



/* Byte order helpers*/

#if defined(__BYTE__ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define HOST_IS_BIG_ENDIAN 1 
#else 
  #define HOST_IS_BIG_ENDIAN 0 
#endif 


static inline uint16_t net_to_host16(uint16_t net){
#if HOST_IS_BIG_ENDIAN 
  return net;
#else 
  return ((net>>8) & 0xFF) | ((net << 8) & 0xFF00);
#endif 
}

static inline uint32_t net_to_host32(uint32_t net) {
#if HOST_IS_BIG_ENDIAN
    return net;
#else
    return ((net >> 24) & 0x000000FF) |
           ((net >> 8)  & 0x0000FF00) |
           ((net << 8)  & 0x00FF0000) |
           ((net << 24) & 0xFF000000);
#endif
}



#define htons(x) net_to_host16(x)
#define ntohs(x) net_to_host16(x)
#define htonl(x) net_to_host32(x)
#define ntohl(x) net_to_host32(x)


#endif 
