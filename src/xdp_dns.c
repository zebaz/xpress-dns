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
#include <stdlib.h>
#include <libbpf.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
//bpf_elf.h is part of iproute2
#include <bpf_elf.h>
#include "common.h"

int get_map_fd(const char *map_path);
void replace_dots_with_length_octets(char *dns_name, char *new_dns_name);
void replace_length_octets_with_dots(char *dns_name, char *new_dns_name);

static const char *a_records_map_path = "/sys/fs/bpf/xdp/globals/xdns_a_records";

void usage(char *progname)
{
    fprintf(stderr, "Usage: %s add record_type domain_name value [ttl]\n", progname);
    fprintf(stderr, "       %s remove record_type domain_name value\n", progname);
    fprintf(stderr, "       %s list\n", progname);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "   %s add a foo.bar 1.2.3.4 120\n", progname);
}

int main(int argc, char **argv)
{
    //Return code
    int ret = EINVAL;

    //Initialize file descriptor for a_records map
    int a_records_fd;
    a_records_fd = get_map_fd(a_records_map_path);
    if (a_records_fd < 0)
        return EXIT_FAILURE;

    if (argc == 2)
    {
        if (strcmp(argv[1], "list") == 0)
        {
            struct dns_query key, next_key;
            struct a_record value;
            int res = -1;
            while (bpf_map_get_next_key(a_records_fd, &key, &next_key) == 0)
            {
                res = bpf_map_lookup_elem(a_records_fd, &next_key, &value);
                if (res > -1)
                {
                    char new_dns_name[strnlen(next_key.name, MAX_DNS_NAME_LENGTH)];
                    replace_length_octets_with_dots(next_key.name, new_dns_name);
                    printf("A %s %s %i\n", new_dns_name, inet_ntoa(value.ip_addr), value.ttl);
                }
                key = next_key;
            }
            ret = 0;
        }
    }
    else if (argc == 5 || argc == 6)
    {
        if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "remove") == 0)
        {
            struct in_addr ip_addr;
            if (inet_aton(argv[4], &ip_addr) == 0)
            {
                printf("ERROR: Invalid IP address\n");
                ret = EFAULT;
                return ret;
            }

            //Create a new dns_name char array
            char new_dns_name[MAX_DNS_NAME_LENGTH];
            //Zero fill the new_dns_name
            memset(&new_dns_name, 0, sizeof(new_dns_name));
            replace_dots_with_length_octets(argv[3], new_dns_name);

            struct dns_query dns;
            dns.class = DNS_CLASS_IN;
            dns.record_type = A_RECORD_TYPE;
            memcpy(dns.name, new_dns_name, sizeof(new_dns_name));

            if (strcmp(argv[1], "add") == 0)
            {
                struct a_record a;
                a.ip_addr = ip_addr;
                if(argc == 5){
                    a.ttl = 0;
                } else {
                    a.ttl = (uint32_t)atoi(argv[5]);
                }
                bpf_map_update_elem(a_records_fd, &dns, &a, BPF_ANY);
                printf("DNS record added\n");
                ret = 0;
            }
            else if (strcmp(argv[1], "remove") == 0)
            {
                if (bpf_map_delete_elem(a_records_fd, &dns) == 0)
                {
                    printf("DNS record removed\n");
                    ret = 0;
                }
                else
                {
                    printf("DNS record not found\n");
                    ret = ENOENT;
                }
            }
        }
    }

    if(ret != 0)
        usage(argv[0]);

    return ret;
}

//Calculate and insert length octets between DNS name labels. RFC1035 4.1.2
void replace_dots_with_length_octets(char *dns_name, char *new_dns_name)
{
    uint16_t name_len = strnlen(dns_name, 255);
    int i;
    int cnt = 0;

    for (i = 0; i <= name_len; i++)
    {
        //If dot character or end of string is detected
        if (dns_name[i] == 46 || dns_name[i] == 0)
        {
            //Put length octet with value [cnt] at location [i-cnt]
            new_dns_name[i - cnt] = cnt;

            //Break loop if zero
            if (dns_name[i] == 0)
            {
                cnt = i + 1;
                break;
            }

            //Reset counter
            cnt = -1;
        }

        new_dns_name[i + 1] = dns_name[i];

        //Count number of characters until the dot character
        cnt++;
    }

    new_dns_name[cnt] = 0;
}

void replace_length_octets_with_dots(char *dns_name, char *new_dns_name)
{
    uint16_t name_len = strnlen(dns_name, 255);

    //Retrieve first label length octet
    char label_length = dns_name[0];
    int i;
    //Loop through dns name, starting at 1 (as position 0 contains length octet)
    for (i = 1; i <= name_len; i++)
    {
        //Break loop if zero
        if (dns_name[i] == 0)
        {
            new_dns_name[i - 1] = 0;
            break;
        }
        else if (label_length == 0)
        {
            new_dns_name[i - 1] = '.';
            //Set label_length to current label length octet
            label_length = dns_name[i];
        }
        else
        {
            new_dns_name[i - 1] = dns_name[i];
            label_length--;
        }
    }
}

int get_map_fd(const char *map_path)
{
    int fd = bpf_obj_get(map_path);
    if (fd < 0)
    {
        if (errno == EACCES)
        {
            printf("ERROR: Permission denied while trying to access %s\n", map_path);
        }
        else if (errno == ENOENT)
        {
            printf("ERROR: Could not find BPF maps. Load XDP program with iproute2 first.\n");
        }
        else
        {
            printf("ERROR: BPF map error: %d (%s)\n", errno, strerror(errno));
        }
    }
    return fd;
}
