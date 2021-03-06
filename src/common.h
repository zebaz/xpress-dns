/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdint.h>

#define A_RECORD_TYPE 0x0001
#define DNS_CLASS_IN 0x0001
//RFC1034: the total number of octets that represent a domain name is limited to 255.
//We need to be aligned so the struct does not include padding bytes. We'll set the length to 256.
//Otherwise padding bytes will generate problems with the verifier, as it ?could contain arbitrary data from memory?
#define MAX_DNS_NAME_LENGTH 256

struct dns_hdr
{
    uint16_t transaction_id;
    uint8_t rd : 1;      //Recursion desired
    uint8_t tc : 1;      //Truncated
    uint8_t aa : 1;      //Authoritive answer
    uint8_t opcode : 4;  //Opcode
    uint8_t qr : 1;      //Query/response flag
    uint8_t rcode : 4;   //Response code
    uint8_t cd : 1;      //Checking disabled
    uint8_t ad : 1;      //Authenticated data
    uint8_t z : 1;       //Z reserved bit
    uint8_t ra : 1;      //Recursion available
    uint16_t q_count;    //Number of questions
    uint16_t ans_count;  //Number of answer RRs
    uint16_t auth_count; //Number of authority RRs
    uint16_t add_count;  //Number of resource RRs
};

#ifdef EDNS
struct ar_hdr {
    uint8_t name;
    uint16_t type;
    uint16_t size;
    uint32_t ex_rcode;
    uint16_t rcode_len;
} __attribute__((packed));
#endif

//Used as key in our hashmap
struct dns_query {
    uint16_t record_type;
    uint16_t class;
    char name[MAX_DNS_NAME_LENGTH];
};

//Used as a generic DNS response
struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class;
   uint32_t ttl;
   uint16_t data_length;
} __attribute__((packed));

//Used as value of our A record hashmap
struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};
