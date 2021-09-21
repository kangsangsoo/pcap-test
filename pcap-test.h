#include <stdint.h>

typedef struct 
{
    u_int8_t  dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t type;                 /* protocol */
}ethernet_hdr;

typedef struct {
    u_int8_t ip[4];
}in_addr;

typedef struct {
    u_int8_t v;         /* version */
    u_int8_t hl;      /* header length */
    u_int8_t tos;       /* type of service */
    u_int16_t len;         /* total length */
    u_int16_t id;          /* identification */
    u_int16_t off;
    u_int8_t ttl;          /* time to live */
    u_int8_t p;            /* protocol */
    u_int16_t sum;         /* checksum */
    in_addr src, dst; /* source and dest address */
}ipv4_hdr;

typedef struct {
    u_int16_t sport;       /* source port */
    u_int16_t dport;       /* destination port */
    u_int32_t seq;          /* sequence number */
    u_int32_t ack;          /* acknowledgement number */
    u_int8_t off;        /* data offset */
    u_int8_t x2;         /* (unused) */
    u_int8_t flags;       /* control flags */
    u_int16_t win;         /* window */
    u_int16_t sum;         /* checksum */
    u_int16_t urp;         /* urgent pointer */
}tcp_hdr;

typedef struct{
    ethernet_hdr ethernet;
    ipv4_hdr ipv4;
    tcp_hdr tcp;
    uint8_t payload[8];
}Header; 
