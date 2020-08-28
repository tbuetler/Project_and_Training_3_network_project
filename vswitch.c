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
 * @file vswitch.c
 * @brief Ethernet switch
 * @author Christian Grothoff
 */
#include "glab.h"
#include "print.c"


/**
 * Maximum number of VLANs supported per interface.
 * (and also by the 802.1Q standard tag).
 */
#define MAX_VLANS 4092

/**
 * Value used to indicate "no VLAN" (or no more VLANs).
 */
#define NO_VLAN (-1)

/**
 * Which VLAN should we assume for untagged frames on
 * interfaces without any specified tag?
 */
#define DEFAULT_VLAN 0

/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;
  uint16_t tag;
};


/**
 * IEEE 802.1Q header.
 */
struct Q
{
  uint16_t tpid; /* must be #ETH_802_1Q_TAG */
  uint16_t tci;
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
   * Number of this interface.
   */
  uint16_t ifc_num;

  /**
   * Name of the network interface, i.e. "eth0".
   */
  char *ifc_name;

  /**
   * Which tagged VLANs does this interface participate in?
   * Array terminated by #NO_VLAN entry.
   */
  int16_t tagged_vlans[MAX_VLANS + 1];

  /**
   * Which untagged VLAN does this interface participate in?
   * #NO_VLAN for none.
   */
  int16_t untagged_vlan;

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
  const uint8_t *framec = frame;
  struct EthernetHeader eh;

  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
	     "Malformed frame\n");
    return;
  }
  memcpy (&eh,
	  frame,
	  sizeof (eh));
  /* DO work here! */
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
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
		size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';
  fprintf (stderr,
           "Received command `%s' (ignored)\n",
           cmd);
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


/**
 * Parse tagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_tagged (const char *start,
	      const char *end,
	      int off,
	      struct Interface *ifc)
{
  char *spec;
  unsigned int pos;

  if (':' != *start)
  {
    fprintf (stderr,
	     "Tagged definition for interface #%d lacks ':'\n",
	     off);
    return 1;
  }
  start++;
  spec = strndup (start,
		  end - start);
  if (NULL == spec)
  {
    perror ("strndup");
    return 1;
  }
  pos = 0;
  for (const char *tok = strtok (spec,
				 ",");
       NULL != tok;
       tok = strtok (NULL,
		     ","))
  {
    unsigned int tag;

    if (pos == MAX_VLANS)
    {
      fprintf (stderr,
	       "Too many VLANs specified for interface #%d\n",
	       off);
      free (spec);
      return 1;
    }
    if (1 != sscanf (tok,
		     "%u",
		     &tag))
    {
      fprintf (stderr,
	       "Expected number in tagged definition for interface #%d\n",
	       off);
      free (spec);
      return 1;
    }
    if (tag > MAX_VLANS)
    {
      fprintf (stderr,
	       "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
	       tag,
	       off);
      free (spec);
      return 1;
    }
    ifc->tagged_vlans[pos++] = (int16_t) tag;
  }
  ifc->tagged_vlans[pos] = NO_VLAN;
  free (spec);
  return 0;
}


/**
 * Parse untagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_untagged (const char *start,
		const char *end,
		int off,
		struct Interface *ifc)
{
  char *spec;
  unsigned int tag;

  if (':' != *start)
  {
    fprintf (stderr,
	     "Untagged definition for interface #%d lacks ':'\n",
	     off);
    return 1;
  }
  start++;
  spec = strndup (start,
		  end - start);
  if (NULL == spec)
  {
    perror ("strndup");
    return 1;
  }
  if (1 != sscanf (spec,
		   "%u",
		   &tag))
  {
    fprintf (stderr,
	     "Expected number in untagged definition for interface #%d\n",
	     off);
    free (spec);
    return 1;
  }
  if (tag > MAX_VLANS)
  {
    fprintf (stderr,
	     "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
	     tag,
	     off);
    free (spec);
    return 1;
  }
  ifc->untagged_vlan = (int16_t) tag;
  free (spec);
  return 0;
}


/**
 * Parse command-line argument with interface specification.
 *
 * @param arg command-line argument
 * @param off offset of @a arg for error reporting
 * @param ifc interface to initialize (ifc_name, tagged_vlans and untagged_vlan).
 * @return 0 on success
 */
static int
parse_vlan_args (const char *arg,
		 int off,
		 struct Interface *ifc)
{
  const char *openbracket;
  const char *closebracket;

  ifc->tagged_vlans[0] = NO_VLAN;
  ifc->untagged_vlan = NO_VLAN;
  openbracket = strchr (arg,
			(unsigned char) '[');
  if (NULL == openbracket)
  {
    ifc->ifc_name = strdup (arg);
    if (NULL == ifc->ifc_name)
    {
      perror ("strdup");
      return 1;
    }
    ifc->untagged_vlan = DEFAULT_VLAN;
    return 0;
  }
  ifc->ifc_name = strndup (arg,
			   openbracket - arg);
  if (NULL == ifc->ifc_name)
  {
    perror ("strndup");
    return 1;
  }
  openbracket++;
  closebracket = strchr (openbracket,
			 (unsigned char) ']');
  if (NULL == closebracket)
  {
    fprintf (stderr,
	     "Interface definition #%d includes '[' but lacks ']'\n",
	     off);
    return 1;
  }
  switch (*openbracket)
  {
  case 'T':
    return parse_tagged (openbracket + 1,
			 closebracket,
			 off,
			 ifc);
    break;
  case 'U':
    return parse_untagged (openbracket + 1,
			   closebracket,
			   off,
			   ifc);
    break;
  default:
    fprintf (stderr,
	     "Unsupported tagged/untagged specification `%c' in interface definition #%d\n",
	     *openbracket,
	     off);
    return 1;
  }
}


#include "loop.c"


/**
 * Launches the vswitch.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc-1];

  (void) print;
  memset (ifc,
	  0,
	  sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i=1;i<argc;i++)
  {
    ifc[i-1].ifc_num = i;
    if (0 !=
	parse_vlan_args (argv[i],
			 i,
			 &ifc[i-1]))
      return 1;
  }
  loop ();
  return 0;
}
