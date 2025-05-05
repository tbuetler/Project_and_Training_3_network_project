/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file arp.c
 * @brief ARP tool
 * @author Christian Grothoff
 */
#include "glab.h"


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma ("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;

  /**
   * See ETH_P-values.
   */
  uint16_t tag;
};


/**
 * ARP header for Ethernet-IPv4.
 */
struct ArpHeaderEthernetIPv4
{
  /**
   * Must be #ARP_HTYPE_ETHERNET.
   */
  uint16_t htype;

  /**
   * Protocol type, must be #ARP_PTYPE_IPV4
   */
  uint16_t ptype;

  /**
   * HLEN.  Must be #MAC_ADDR_SIZE.
   */
  uint8_t hlen;

  /**
   * PLEN.  Must be sizeof (struct in_addr) (aka 4).
   */
  uint8_t plen;

  /**
   * Type of the operation.
   */
  uint16_t oper;

  /**
   * HW address of sender. We only support Ethernet.
   */
  struct MacAddress sender_ha;

  /**
   * Layer3-address of sender. We only support IPv4.
   */
  struct in_addr sender_pa;

  /**
   * HW address of target. We only support Ethernet.
   */
  struct MacAddress target_ha;

  /**
   * Layer3-address of target. We only support IPv4.
   */
  struct in_addr target_pa;
};

_Pragma("pack(pop)")


/**
 * Per-interface context.
 */
struct Interface
{
  /**
   * MAC of interface.
   */
  struct MacAddress mac;

  /**
   * IPv4 address of interface (we only support one IP per interface!)
   */
  struct in_addr ip;

  /**
   * IPv4 netmask of interface.
   */
  struct in_addr netmask;

  /**
   * Name of the interface.
   */
  char *name;

  /**
   * Interface number.
   */
  uint16_t ifc_num;

  /**
   * MTU to enforce for this interface.
   */
  uint16_t mtu;
};


/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;


/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to (struct Interface *dst,
            const void *frame,
            size_t frame_size)
{
  char iob[frame_size + sizeof (struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  if (frame_size > dst->mtu)
    abort ();
  hdr.size = htons (sizeof (iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
          &hdr,
          sizeof (hdr));
  memcpy (&iob[sizeof (hdr)],
          frame,
          frame_size);
  write_all (STDOUT_FILENO,
             iob,
             sizeof (iob));
}


/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame (struct Interface *ifc,
             const void *frame,
             size_t frame_size)
{
  struct EthernetHeader eh;
  struct ArpHeaderEthernetIPv4 ah;
  const char *cframe = frame;

// check if the frame size is at least the size of an Ethernet header
  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
             "Malformed frame\n");
    return;
  }

  // copy the ethernet header from the frame
  memcpy (&eh,
          frame,
          sizeof (eh));
  /* DO WORK HERE */

// TODO: work done by tim - just in case there are errors :)
  // check if the ethernet frame contains an ARP packet (ethernet type 0x0806)
  if (ntohs (eh.tag) != 0x0806) // check if it's an ARP packet
    return;

  // copy the ARP header from the frame
  memcpy (&ah,cframe + sizeof(eh), sizeof (ah));

  // validate the ARP packet fields
  if (ntohs(ah.htype) != 1                      // HW type must be ethernet
      || ntohs(ah.ptype) != 0x0800              // protocol type must be IPv4
      || ah.hlen != MAC_ADDR_SIZE               // HW address length must be MAC_ADDR_SIZE
      || ah.plen != sizeof(struct in_addr))     // protocol address length must match IPv4 size
  {
    fprintf (stderr, "Malformed frame\n");
    return;
  }

  // check if the ARP operation is a request (1)
  if (ntohs(ah.oper) == 1) // ARP request
  {
    // verify if the target IP address matches the interface's IP address
    if (memcmp(&ah.target_pa, &ifc->ip, sizeof(struct in_addr)) == 0)
    {
      // create ARP reply
      struct EthernetHeader reply_eh;
      struct ArpHeaderEthernetIPv4 reply_ah;

      // set ethernet header fields
      reply_eh.dst = eh.src;                    // destination MAC is the source MAC of the request
      reply_eh.src = ifc->mac;                  // source MAC is the interface's MAC address
      reply_eh.tag = ntohs(0x806);              // ethernet type for ARP

      // set ARP header fields
      reply_ah.htype = htons(1);                // HW type is ethernet
      reply_ah.ptype = htons(0x0800);           // protocol type is IPv4
      reply_ah.hlen = MAC_ADDR_SIZE;            // HW address length is MAC_ADDR_SIZE
      reply_ah.plen = sizeof(struct in_addr);   // protocol address length is IPv4 size
      reply_ah.oper = htons(2);                 // operation is reply
      reply_ah.sender_ha = ifc->mac;            // sender MAC is the interface's MAC address
      reply_ah.sender_pa = ifc->ip;             // sender IP is the interface's IP address
      reply_ah.target_ha = ah.sender_ha;        // target MAC is the sender MAC
      reply_ah.target_pa = ah.sender_pa;        // target IP is the sender IP

      // combine ethernet and ARP headers into a single frame
      char reply_frame[sizeof(reply_eh) + sizeof(reply_ah)];
      memcpy(reply_frame, &reply_eh, sizeof(reply_eh));
      memcpy(reply_frame + sizeof(reply_eh), &reply_ah, sizeof(reply_ah));

      // send the ARP reply
      forward_to(ifc, reply_frame, sizeof(reply_frame));
    }
  }
  // check if the ARP operation is a reply (2)
  else if (ntohs(ah.oper) == 2) // ARP reply
  {
    // TODO: store senders MAC and IP in ARP cache
    add_to_arp_cache(&ah.sender_ha, &ah.sender_pa);
  }
}


/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
static void
handle_frame (uint16_t interface,
              const void *frame,
              size_t frame_size)
{
  if (interface > num_ifc)
    abort ();
  parse_frame (&gifc[interface - 1],
               frame,
               frame_size);
}


/**
 * The user entered an "arp" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void
process_cmd_arp ()
{
  const char *tok = strtok (NULL, " ");
  struct in_addr v4;
  struct MacAddress mac;
  struct Interface *ifc;

  if (NULL == tok)
  {
    // print_arp_cache ();
    return;
  }
  if (1 !=
      inet_pton (AF_INET,
                 tok,
                 &v4))
  {
    fprintf (stderr,
             "`%s' is not a valid IPv4 address\n",
             tok);
    return;
  }
  tok = strtok (NULL, " ");
  if (NULL == tok)
  {
    fprintf (stderr,
             "No network interface provided\n");
    return;
  }
  ifc = NULL;
  for (unsigned int i = 0; i<num_ifc; i++)
  {
    if (0 == strcasecmp (tok,
                         gifc[i].name))
    {
      ifc = &gifc[i];
      break;
    }
  }
  if (NULL == ifc)
  {
    fprintf (stderr,
             "Interface `%s' unknown\n",
             tok);
    return;
  }
  /* do MAC lookup */
}


/**
 * Parse network specification in @a net, initializing @a ifc.
 * Format of @a net is "IPV4:IP/NETMASK".
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network (struct Interface *ifc,
               const char *net)
{
  const char *tok;
  char *ip;
  unsigned int mask;

  if (0 !=
      strncasecmp (net,
                   "IPV4:",
                   strlen ("IPV4:")))
  {
    fprintf (stderr,
             "Interface specification `%s' does not start with `IPV4:'\n",
             net);
    return 1;
  }
  net += strlen ("IPV4:");
  tok = strchr (net, '/');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification `%s': lacks '/'\n",
             net);
    return 1;
  }
  ip = strndup (net,
                tok - net);
  if (1 !=
      inet_pton (AF_INET,
                 ip,
                 &ifc->ip))
  {
    fprintf (stderr,
             "IP address `%s' malformed\n",
             ip);
    free (ip);
    return 1;
  }
  free (ip);
  tok++;
  if (1 !=
      sscanf (tok,
              "%u",
              &mask))
  {
    fprintf (stderr,
             "Netmask `%s' malformed\n",
             tok);
    return 1;
  }
  if (mask > 32)
  {
    fprintf (stderr,
             "Netmask invalid (too large)\n");
    return 1;
  }
  ifc->netmask.s_addr = htonl (~(uint32_t) ((1LLU << (32 - mask)) - 1LLU));
  return 0;
}


/**
 * Parse interface specification @a arg and update @a ifc.  Format is
 * "IFCNAME[IPV4:IP/NETMASK]=MTU".  The "=MTU" is optional.
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_cmd_arg (struct Interface *ifc,
               const char *arg)
{
  const char *tok;
  char *nspec;

  ifc->mtu = 1500 + sizeof (struct EthernetHeader); /* default in case unspecified */
  tok = strchr (arg, '[');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks '['");
    return 1;
  }
  ifc->name = strndup (arg,
                       tok - arg);
  arg = tok + 1;
  tok = strchr (arg, ']');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks ']'");
    return 1;
  }
  nspec = strndup (arg,
                   tok - arg);
  if (0 !=
      parse_network (ifc,
                     nspec))
  {
    free (nspec);
    return 1;
  }
  free (nspec);
  arg = tok + 1;
  if ('=' == arg[0])
  {
    unsigned int mtu;

    if (1 != (sscanf (&arg[1],
                      "%u",
                      &mtu)))
    {
      fprintf (stderr,
               "Error in interface specification: MTU not a number\n");
      return 1;
    }
    if (mtu < 400)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too small\n");
      return 1;
    }
    ifc->mtu = mtu + sizeof (struct EthernetHeader);
  }
  return 0;
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
                size_t cmd_len)
{
  const char *tok;

  cmd[cmd_len - 1] = '\0';
  tok = strtok (cmd,
                " ");
  if (0 == strcasecmp (tok,
                       "arp"))
    process_cmd_arp ();
  else
    fprintf (stderr,
             "Unsupported command `%s'\n",
             tok);
}


/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac (uint16_t ifc_num,
            const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;
}


// TODO: Built an arp cache by tim
#define ARP_CACHE_SIZE 256  // Size of the ARP cache

struct ArpCacheEntry {
    struct in_addr ip;      // IPv4 address
    struct MacAddress mac;  // MAC address
    int valid;              // Entry validity flag
};

// static array to store the ARP cache entries
static struct ArpCacheEntry arp_cache[ARP_CACHE_SIZE];

/**
 * Hash function for IP addresses.
 * This function computes a hash value for an IPv4 address to determine its index in the ARP cache.
 * *Disclaimer: This idea has been provided by an AI*
 */
static unsigned int hash_ip(const struct in_addr *ip) {
    return ntohl(ip->s_addr) % ARP_CACHE_SIZE;  // use modulo operation to limit the index
}

/**
 * Add an entry to the ARP cache.
 * This function updates the ARP cache with the given IP address and MAC address.
 * If an entry already exists for the IP, it is overwritten
 */
void add_to_arp_cache(const struct in_addr *ip, const struct MacAddress *mac) {
    unsigned int index = hash_ip(ip);   // compute the index using the hash function
    arp_cache[index].ip = *ip;          // store the IP address in the cache
    arp_cache[index].mac = *mac;        // store the MAC address in the cache
    arp_cache[index].valid = 1;         // mark the entry as valid
}

/**
 * Remove an entry from the ARP cache.
 */
void remove_from_arp_cache(const struct in_addr *ip) {
    unsigned int index = hash_ip(ip);
    if (arp_cache[index].valid && memcmp(&arp_cache[index].ip, ip, sizeof(struct in_addr)) == 0) {
        arp_cache[index].valid = 0;
    }
}

/**
 * Lookup a MAC address in the ARP cache by IP.
 */
struct MacAddress *lookup_arp_cache(const struct in_addr *ip) {
    unsigned int index = hash_ip(ip);
    if (arp_cache[index].valid && memcmp(&arp_cache[index].ip, ip, sizeof(struct in_addr)) == 0) {
        return &arp_cache[index].mac;
    }
    return NULL;
}


/**
 * Launches the arp tool.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc];

  memset (ifc,
          0,
          sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i = 1; i<argc; i++)
  {
    struct Interface *p = &ifc[i - 1];

    ifc[i - 1].ifc_num = i;
    if (0 !=
        parse_cmd_arg (p,
                       argv[i]))
      abort ();
  }
  loop (&handle_frame,
        &handle_control,
        &handle_mac);
  for (unsigned int i = 1; i<argc; i++)
    free (ifc[i - 1].name);
  return 0;
}
