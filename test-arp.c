/*
     This file is part of the ARP testing suite.
     Copyright (C) 2023

     This program is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     This program is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file test-arp.c
 * @brief Testcase for the ARP implementation. Must be linked with harness.c.
 */

#include "harness.h"

/**
 * Set to 1 to enable debug statements.
 */
#define DEBUG 0

/**
 * Test adding and looking up an ARP entry.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_add_lookup_arp(const char *prog)
{
  struct in_addr ip;
  struct MacAddress mac;
  struct MacAddress *result;

  inet_pton(AF_INET, "192.168.1.1", &ip);
  mac.addr[0] = 0x00;
  mac.addr[1] = 0x11;
  mac.addr[2] = 0x22;
  mac.addr[3] = 0x33;
  mac.addr[4] = 0x44;
  mac.addr[5] = 0x55;

  add_to_arp_cache(&ip, &mac);
  result = lookup_arp_cache(&ip);

  if (result && memcmp(result, &mac, sizeof(struct MacAddress)) == 0)
    return 0;

  fprintf(stderr, "Failed to add or lookup ARP entry\n");
  return 1;
}

/**
 * Test removing an ARP entry.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_remove_arp(const char *prog)
{
  struct in_addr ip;
  struct MacAddress mac;

  inet_pton(AF_INET, "192.168.1.1", &ip);
  mac.addr[0] = 0x00;
  mac.addr[1] = 0x11;
  mac.addr[2] = 0x22;
  mac.addr[3] = 0x33;
  mac.addr[4] = 0x44;
  mac.addr[5] = 0x55;

  add_to_arp_cache(&ip, &mac);
  remove_from_arp_cache(&ip);

  if (lookup_arp_cache(&ip) == NULL)
    return 0;

  fprintf(stderr, "Failed to remove ARP entry\n");
  return 1;
}

/**
 * Test ARP cache collision handling.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_arp_collision(const char *prog)
{
  struct in_addr ip1, ip2;
  struct MacAddress mac1, mac2;

  inet_pton(AF_INET, "192.168.1.1", &ip1);
  inet_pton(AF_INET, "192.168.1.2", &ip2);

  mac1.addr[0] = 0x00;
  mac1.addr[1] = 0x11;
  mac1.addr[2] = 0x22;
  mac1.addr[3] = 0x33;
  mac1.addr[4] = 0x44;
  mac1.addr[5] = 0x55;

  mac2.addr[0] = 0x66;
  mac2.addr[1] = 0x77;
  mac2.addr[2] = 0x88;
  mac2.addr[3] = 0x99;
  mac2.addr[4] = 0xAA;
  mac2.addr[5] = 0xBB;

  add_to_arp_cache(&ip1, &mac1);
  add_to_arp_cache(&ip2, &mac2);

  if (lookup_arp_cache(&ip1) && lookup_arp_cache(&ip2))
    return 0;

  fprintf(stderr, "Failed to handle ARP cache collision\n");
  return 1;
}

/**
 * Call with path to the ARP program to test.
 */
int
main(int argc, char **argv)
{
  unsigned int grade = 0;
  unsigned int possible = 0;
  struct Test
  {
    const char *name;
    int (*fun)(const char *arg);
  } tests[] = {
    { "add and lookup ARP entry", &test_add_lookup_arp },
    { "remove ARP entry", &test_remove_arp },
    { "ARP cache collision", &test_arp_collision },
    { NULL, NULL }
  };

  if (argc != 2)
  {
    fprintf(stderr, "Call with ARP program to test as 1st argument!\n");
    return 1;
  }
  for (unsigned int i = 0; NULL != tests[i].fun; i++)
  {
    if (0 == tests[i].fun(argv[1]))
      grade++;
    else
      fprintf(stdout, "Failed test `%s'\n", tests[i].name);
    possible++;
  }
  fprintf(stdout, "Final grade: %u/%u\n", grade, possible);
  if (grade < possible)
    return 1;
  return 0;
}