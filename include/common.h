#ifndef COMMON_H
#define COMMON_H 


// Common definitions 


#include <stdint.h>
#include "platform.h"



// Maximum entries in BPF maps

#define MAX_ENTRIES 65536 
#define MAX_TRACKED_IPS 8192
#define MAX_TRACKED_PORTS 1024
#define MAX_TRACKED_FLOWS 16384
#define MAX_CPU_COUNT 256


// Ring buffer size must be power of 2 
#define RING_BUFFER_SIZE (i << 20) // 1MB


// Event type sent from the kernel to userpsace


enum event_type{
  EVENT_PACKET_IPV4 = 1,
  EVENT_PACKET_IPV6 = 2,
  EVENT_TCP_CONNECT = 3,
  EVENT_TCP_CLOSE = 4,
  EVENT_UDP_SEND = 5,
  EVENT_UDP_RECV = 6,
  EVENT_ICMP = 7,
  EVENT_ARP = 8,
  EVENT_ANOMALY = 9,
  EVENT_STATS_UPDATE = 10,
};


// Anomaly types for detection

enum anomaly_type{
  ANOMALY_NONE = 0,
  ANOMALY_SYN_FLOOD = 1,
  ANOMALY_PORT_SCAN = 2,
  ANOMALY_ICMP_FLOOD = 3,
  ANOMALY_UDP_FLOOD =4,
  ANOMALY_DNS_AMPLIFY = 5,
  ANOMALY_UNUSUAL_PORT = 6,
  ANOMALY_RATE_EXCEEDED = 7,
};


// PACKET direction 

enum packet_direction{
  DIR_UNKNOWN = 0,
  DIR_INGRESS = 1,
  DIR_EGRESS = 2,
};


// IP statistics key

struct ip_stats_key {
  uint32_t ip_addr;
}PACKED;



// Ip statistics value

struct ip_stats_value {
  uint64_t packets_in;
  uint64_t packets_out;
  uint64_t bytes_in;
  uint64_t bytes_out;
  uint64_t tcp_count;
  uint64_t udp_count;
  uint64_t icmp_count;
  uint64_t other_count;
  uint64_t syn_count; // For SYN flood detection 
  uint64_t last_seen_ns; // Timstamp in nanoseconds
} PACKED  ALIGNED(8);




// Port statistics key


struct port_stats_key{
  uint16_t port;
  uint8_t protocol; // TCP or UDP
  uint8_t pad;
} PACKED;


// Port statistics value 
struct port_stats_value{
  uint64_t packets;
  uint64_t bytes;
  uint64_t connections;
  uint64_t last_seen_ns;
}PACKED ALIGNED(8);



// Global Statistics (per-CPU)


struct global_Stats{
  // Packet Counts 
  uint64_t total_packets;
  uint64_t total_bytes;
  // By protocol
  uint64_t ipv4_packets;
  uint64_t ipv6_packets;
  uint64_t tcp_packets;
  uint64_t udp_packets;
  uint64_t icmp_packets;
  uint64_t arp_packets;
  uint64_t other_packets;
  // TCP Flags
  uint64_t tcp_syn;
  uint64_t tcp_synack;
  uint64_t tcp_fin;
  uint64_t tcp_rst;
  uint64_t tcp_ack;

  // Errors and drops 
  uint64_t parse_errors;
  uint64_t drops;

  // Anomalies Detected
  uint64_t anomalies;

  // Timestamp
  uint64_t last_update_ns;
 } ALIGNED(CACHE_LINE_SIZE);




// Event structure for ring buffer

struct packet_event{

  // Event Metadata
  uint32_t event_type;
  uint32_t event_flags;
  uint64_t timestamp_ns;

  // Packet Info
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protcol;
  uint8_t direction;
  uint16_t pkt_len;


  // TCP Specific

  uint8_t tcp_flags;
  uint8_t pad[3];


  // Anomaly Information
  uint32_t anomaly_type;
  uint32_t anomaly_score;


  // Interface information
  uint32_t ifindex;
} PACKED ALIGNED(8);



// Configuration passed to BPF program

struct observer_config{
  
  uint32_t flags;
  uint32_t sample_rate; // 1 = all , N = 1/N sampling 
  uint32_t syn_threshold; // Syn packets per second for alert;
  uint32_t port_scan_threshold; 
  uint32_t rate_limit_pps; // Packets per second limit 
  uint32_t rate_limit_bps; // Bytes per second limit;
  uint16_t watched_ports[16]; // Ports to specifically monitor;
   uint8_t watched_port_count; 
  uint8_t pad[3];
}ALIGNED(8);



// Configuration Flags
#define CONFIG_FLAG_ENABLED      (1 << 0)
#define CONFIG_FLAG_SAMPLE       (1 << 1)
#define CONFIG_FLAG_DETECT_SCAN  (1 << 2)
#define CONFIG_FLAG_DETECT_FLOOD (1 << 3)
#define CONFIG_FLAG_LOG_ALL      (1 << 4)
#define CONFIG_FLAG_IPV4_ONLY    (1 << 5)
#define CONFIG_FLAG_IPV6_ONLY    (1 << 6)
#define CONFIG_FLAG_TCP_ONLY     (1 << 7)
#define CONFIG_FLAG_UDP_ONLY     (1 << 8)


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MIN(a,b) ((a)<(b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))


#endif
