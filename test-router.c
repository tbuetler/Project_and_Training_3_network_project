#include "harness.h"
#include "glab.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>

#define DEBUG 1

// Required structure definitions
struct Interface {
    struct MacAddress mac;
    struct in_addr ip;
    struct in_addr netmask;
    char *name;
    uint16_t ifc_num;
    uint16_t mtu;
};

struct IPv4Header {
    unsigned int header_length : 4;
    unsigned int version : 4;
    uint8_t diff_serv;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragmentation_info;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr source_address;
    struct in_addr destination_address;
};

void route(struct Interface *origin,
                 const struct IPv4Header *ip,
                 const void *payload,
                 size_t payload_size)
{
    print("Test route function called\n");
    print("Origin interface: %s\n", origin->name);
    print("Destination IP: %s\n", inet_ntoa(ip->destination_address));
    print("Payload size: %zu\n", payload_size);
};


/**
 * Test method 1: Basic routing functionality
 */
static int
test_basic_routing_functionality(const char *arg)
{
    struct Interface *ifc = malloc(sizeof(struct Interface));
    struct IPv4Header *ip = malloc(sizeof(struct IPv4Header));
    char payload[64] = "Test payload\n";

    // Initialize mock interface
    memset(ifc, 0, sizeof(struct Interface));
    ifc->name = strdup("eth0\n");
    ifc->mtu = 1500;
    inet_pton(AF_INET, "192.168.1.1\n", &ifc->ip);

    // Set up test IP header
    memset(ip, 0, sizeof(struct IPv4Header));
    ip->version = 4;
    ip->header_length = 5;
    ip->ttl = 64;
    inet_pton(AF_INET, "192.168.1.100\n", &ip->destination_address);

    print("Testing routing for destination IP %s\n", inet_ntoa(ip->destination_address));

    // Test routing function
    route(ifc, ip, payload, sizeof(payload));

    free(ifc->name);
    free(ifc);
    free(ip);
    return 0;
}

int
main(int argc, char **argv)
{
    unsigned int grade = 0;
    unsigned int possible = 0;
    struct Test {
        const char *name;
        int (*fun)(const char *arg);
    } tests[] = {
        { "test_basic_routing_functionality\n", &test_basic_routing_functionality },
        { NULL, NULL }
    };

    if (argc != 2) {
        fprintf(stderr, "Call with router program to test as 1st argument!\n");
        return 1;
    }

    for (unsigned int i = 0; NULL != tests[i].fun; i++) {
        if (0 == tests[i].fun(argv[1])) {
            grade++;
            printf("Test '%s' passed\n", tests[i].name);
        } else {
            fprintf(stdout, "Failed test `%s'\n", tests[i].name);
        }
        possible++;
    }

    fprintf(stdout, "Final grade: %u/%u\n", grade, possible);
    if (grade < possible)
        return 1;
    return 0;
}