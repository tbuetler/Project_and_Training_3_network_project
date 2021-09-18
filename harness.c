/*
     This file (was) part of GNUnet.
     Copyright (C) 2018, 2021 Christian Grothoff

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
 * @file harness.c
 * @brief Testing and grading harness
 * @author Christian Grothoff
 */
#include "harness.h"
#include "print.c"
#include <limits.h>

/**
 * Set to 1 to enable debug statments.
 */
#define DEBUG 1


/**
 * STDIN of child process (to be written to).
 */
static int child_stdin;

/**
 * STDOUT of child process (to be read from).
 */
static int child_stdout;

/**
 * Input buffer for reading from #child_stdout.
 */
static char child_buf[65536];

/**
 * Our current offset for reading into #child_buf.
 */
static size_t child_buf_pos;

/**
 * List of our MAC addresses
 */
static struct MacAddress *gifcs;

/**
 * Length of the #gifcs array.
 */
static uint16_t num_ifcs;


/**
 * We expect a frame with body @a cls1 of length @a cls2
 * on interface @e cls3 on all interfaces where the
 * bits are set in the 64-bit bitmask stored at @a cls.
 *
 * @param cls closure with bitmask of interfaces to receive on
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls frame we expect
 * @param cls2 length of @a cls
 * @param cls3 ignored
 * @return 0 on success, 1 on missmatch (or not yet complete)
 */
int
expect_multicast (void *cls,
                  uint16_t ifc,
                  const void *msg,
                  size_t msg_len,
                  const void *cls1,
                  ssize_t cls2,
                  uint16_t cls3)
{
  uint64_t *all = cls;

  if (0 == ifc)
  {
    fprintf (stderr,
             "Received bogus text output\n");
    return 2;
  }
  if ( (ifc >= 64) ||
       (0 == ((*all) & (1 << (ifc - 1)))) )
  {
#if DEBUG
    fprintf (stderr,
             "Interface %u does not match MC expectations %llu (len: %u)\n",
             (unsigned int) ifc,
             (unsigned long long) *all,
             (unsigned int) msg_len);
#endif
    return 1;   /* missmatch */
  }
  if (0 !=
      expect_frame (NULL,
                    ifc,
                    msg,
                    msg_len,
                    cls1,
                    cls2,
                    ifc))
    return 1;   /* missmatch */
  *all -= (1 << (ifc - 1));
#if DEBUG
  fprintf (stderr,
           "Interface %u does match MC expectations %llu (len: %u)\n",
           (unsigned int) ifc,
           (unsigned long long) *all,
           (unsigned int) msg_len);
#endif
  if (0 == *all)
    return 0;
  return 1; /* more expected */
}


/**
 * We expect text output @a cls.
 *
 * @param cls closure
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls1 text we expect
 * @param cls2 unused
 * @param cls3 unused
 * @return 0 on success, 1 on missmatch
 */
int
expect_text (void *cls,
             uint16_t ifc,
             const void *msg,
             size_t msg_len,
             const void *cls1,
             ssize_t cls2,
             uint16_t cls3)
{
  const char *text = cls1;

  if (0 != ifc)
  {
    fprintf (stderr,
             "Expected `%s', got frame on interface %u\n",
             text,
             (unsigned int) ifc);
    return 1;
  }
  if ( (msg_len != strlen (text)) ||
       (0 != strncasecmp (text,
                          msg,
                          msg_len)) )
  {
    fprintf (stderr,
             "Expected `%s', got `%.*s'\n",
             text,
             (int) msg_len,
             (const char *) msg);
    return 1;
  }
  return 0;
}


/**
 * Send command to program under test.
 *
 * @param cmd command string (without '\n')
 */
void
send_command (const char *cmd)
{
  char *dp;
  size_t slen;

  /* format requires \n-termination instead of \0-termination */
  slen = strlen (cmd);
  dp = strdup (cmd);
  dp[slen] = '\n';
  tsend (0,
         dp,
         slen + 1);
  free (dp);
}


/**
 * We expect a frame with body @a cls1 of length @a cls2
 * on interface @e cls3.
 *
 * @param cls closure
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls frame we expect
 * @param cls2 length of @a cls, negative to indicate that
 *             the @a msg may be longer, and in that case
 *             the 'padding' should be ignored!
 * @param cls3 interface we expect to receive from
 * @return 0 on success, 1 on missmatch
 */
int
expect_frame (void *cls,
              uint16_t ifc,
              const void *msg,
              size_t msg_len,
              const void *cls1,
              ssize_t cls2,
              uint16_t cls3)
{
  unsigned int off;

  if (0 == ifc)
  {
    fprintf (stderr,
             "Received bogus text output\n");
    return 2;
  }
  if ( (cls3 == ifc) &&
       ( (cls2 < 0) &&
         (msg_len >= -cls2) ) &&
       (0 == memcmp (msg,
                     cls1,
                     -cls2)) )
    return 0;
  if ( (cls3 == ifc) &&
       (msg_len == cls2) &&
       (0 == memcmp (msg,
                     cls1,
                     cls2)) )
    return 0;
  off = UINT_MAX;
  fprintf (stderr,
           "BAD: ");
  if ( (cls3 == ifc) &&
       (msg_len == cls2) )
  {
    const uint8_t *b1 = msg;
    const uint8_t *b2 = cls1;

    for (unsigned int i = 0; i<msg_len; i++)
    {
      fprintf (stderr,
               "%c",
               b1[i] != b2[i] ? 'X' : '.');
      if ( (b1[i] != b2[i]) &&
           (UINT_MAX == off) )
        off = i;
    }
  }
  fprintf (stderr,
           "\n");
#if DEBUG
  fprintf (stderr,
           "Received unexpected %u (want: %d) byte frame (%d/%d/%u) on interface %u\n",
           (unsigned int) msg_len,
           (int) cls2,
           (cls3 == ifc),
           (msg_len == cls2),
           off,
           ifc);
#endif
  return 1;
}


#include "crc.c"

/**
 * Set destination MAC in @a frame to the MAC of
 * interface @a ifc_num.
 *
 * @param frame[in,out] Ethernet frame, must be large enough
 * @param ifc_num identifies which MAC we should use
 */
void
set_dest_mac (void *frame,
              uint16_t ifc_num)
{
  struct EthernetHeader eh;

  if ( (0 == ifc_num) ||
       (ifc_num - 1 >= num_ifcs) )
    abort ();
  memcpy (&eh,
          frame,
          sizeof (eh));
  eh.dst = gifcs[ifc_num - 1];
  memcpy (frame,
          &eh,
          sizeof (eh));
}


/**
 * Calculate checksum.
 *
 * @param ip header to fix checksum for.
 */
void
calc_ipv4_checksum (struct IPv4Header *ip)
{
  ip->checksum = 0;
  ip->checksum = GNUNET_CRYPTO_crc16_n (ip,
                                        sizeof (struct IPv4Header));
}


/**
 * We expect a frame with body @a cls of length @a cls2
 * on interface @e cls3.  We expect IP fragments, so
 * check the IP header and see if the body matches.
 *
 * @param cls bitmask of fragments to expect (high 32 bits) plus MTU
 * @param ifc interface we got a frame from
 * @param msg frame we received (just a fragment)
 * @param msg_len number of bytes in @a msg
 * @param cls1 frame we expect (entire frame)
 * @param cls2 length of @a cls
 * @param cls3 interface we expect to receive from
 * @return 0 on success, 1 on missmatch
 */
int
expect_fragment (void *cls,
                 uint16_t ifc,
                 const void *msg,
                 size_t msg_len,
                 const void *cls1,
                 ssize_t cls2,
                 uint16_t cls3)
{
  uint64_t *fdata = cls;
  uint32_t mtu = (*fdata & UINT32_MAX) - sizeof (struct EthernetHeader);
  uint32_t fbitmask = (*fdata >> 32);
  uint32_t foff;
  const char *mbuf = msg;
  const char *xbuf = cls1;
  struct IPv4Header msg_hdr;
  struct IPv4Header exp_hdr;
  uint32_t fcnt;
  uint32_t fsize;

  if (0 == ifc)
  {
    fprintf (stderr,
             "Received bogus text output\n");
    return 2;
  }
  if (ifc != cls3)
  {
    fprintf (stderr,
             "Received message on unexpected interface %u\n",
             (unsigned int) ifc);
    return 1;
  }
  if (msg_len < sizeof (struct EthernetHeader) + sizeof (struct IPv4Header))
  {
    fprintf (stderr,
             "Received %u byte message on interface %u is too small\n",
             (unsigned int) msg_len,
             (unsigned int) ifc);
    return 1;
  }
  if (0 != memcmp (msg,
                   cls1,
                   sizeof (struct EthernetHeader)))
  {
    fprintf (stderr,
             "Ethernet header missmatch on interface %u\n",
             (unsigned int) ifc);
    return 1;
  }
  memcpy (&msg_hdr,
          &mbuf[sizeof (struct EthernetHeader)],
          sizeof (msg_hdr));
  memcpy (&exp_hdr,
          &xbuf[sizeof (struct EthernetHeader)],
          sizeof (exp_hdr));
  if ( (msg_hdr.header_length != exp_hdr.header_length) ||
       (msg_hdr.version != exp_hdr.version) ||
       (msg_hdr.diff_serv != exp_hdr.diff_serv) ||
       (msg_hdr.identification != exp_hdr.identification) ||
       (msg_hdr.ttl != exp_hdr.ttl) ||
       (msg_hdr.protocol != exp_hdr.protocol) ||
       (msg_hdr.source_address.s_addr != exp_hdr.source_address.s_addr) ||
       (msg_hdr.destination_address.s_addr !=
        exp_hdr.destination_address.s_addr) )
  {
    fprintf (stderr,
             "IP header basic missmatch on interface %u\n",
             (unsigned int) ifc);
    return 1;
  }
  if (ntohs (msg_hdr.total_length) > mtu)
  {
    fprintf (stderr,
             "IP fragment of size %u (msg_len: %u) exceeds MTU\n",
             (unsigned int) ntohs (msg_hdr.total_length),
             (unsigned int) msg_len);
    return 1;
  }
  if (ntohs (msg_hdr.total_length) != msg_len - sizeof (struct EthernetHeader))
  {
    fprintf (stderr,
             "IP header total_length %u does not match frame size\n",
             (unsigned int) ntohs (msg_hdr.total_length));
    return 1;
  }
  foff = (ntohs (msg_hdr.fragmentation_info) & ~IP_FLAGS)
         * IP_FRAGMENT_MULTIPLE;
  foff -= (ntohs (exp_hdr.fragmentation_info) & ~IP_FLAGS)
          * IP_FRAGMENT_MULTIPLE;
  if ( (foff + msg_len > cls2) ||
       (foff + msg_len < foff) )
  {
    fprintf (stderr,
             "Fragmentation offset %u (-%u) way too big (or small) for payload (%u/%u)\n",
             (unsigned int) (ntohs (msg_hdr.fragmentation_info) & ~IP_FLAGS)
             * IP_FRAGMENT_MULTIPLE,
             (ntohs (exp_hdr.fragmentation_info) & ~IP_FLAGS)
             * IP_FRAGMENT_MULTIPLE,
             (unsigned int) msg_len,
             (unsigned int) cls2
             );
    return 1;
  }
  if  (0 != memcmp (&xbuf[sizeof (struct EthernetHeader)
                          + sizeof (struct IPv4Header) + foff],
                    &mbuf[sizeof (struct EthernetHeader)
                          + sizeof (struct IPv4Header)],
                    msg_len - sizeof (struct EthernetHeader) - sizeof (struct
                                                                       IPv4Header)))
  {
    fprintf (stderr,
             "Fragment at offset %u (%u) does not match expected payload\n",
             (unsigned int) foff,
             (ntohs (exp_hdr.fragmentation_info) & ~IP_FLAGS)
             * IP_FRAGMENT_MULTIPLE);
    return 1;
  }
  if (cls2 == msg_len + foff)
  {
    /* last fragment */
    if (0 != (ntohs (msg_hdr.fragmentation_info) & IP_FLAGS_MORE_FRAGMENTS))
    {
      fprintf (stderr,
               "MF bit set in last fragment\n");
      return 1;
    }
  }
  else
  {
    /* not last fragment */
    if (0 == (ntohs (msg_hdr.fragmentation_info) & IP_FLAGS_MORE_FRAGMENTS))
    {
      fprintf (stderr,
               "MF bit NOT set, but there must be more fragments!\n");
      return 1;
    }
  }
  /* TODO: check IP checksum... */

  /* Calculate optimum fragment size, use that to estimate which
     fragment number this is for the bitmask update! */
  fsize = mtu - sizeof (struct IPv4Header);
  fsize = (fsize / 8) * 8; /* must be multiple of 8 */
  if (0 != (foff % fsize))
    fprintf (stderr,
             "Sub-optimal fragmentation (%u/%u/%u), heuristic to guess fragment # fails!\n",
             mtu,
             fsize,
             foff);
  fcnt = (foff / fsize);
  if (0 == (fbitmask & (1LLU << fcnt)))
  {
    fprintf (stderr,
             "Got fragment %u twice!\n",
             (unsigned int) fcnt);
    return 1;
  }
  fbitmask -= (1LLU << fcnt);
  *fdata = (((unsigned long long) fbitmask) << 32) | (mtu + sizeof (struct
                                                                    EthernetHeader));
  if (0 == fbitmask)
    return 0;
  return 1; /* expecting still more fragments */
}


/**
 * We expect a frame with body @a cls of length @a cls2
 * on interface @e cls3.  As this is an ICMP response,
 * the length of the body payload may differ (@e msg_len
 * may be shorter, but must at least contain 8 bytes
 * of the original payload).  Also, the IP identifier
 * should be ignored.
 *
 * @param cls closure
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls1 frame we expect
 * @param cls2 length of @a cls
 * @param cls3 interface we expect to receive from
 * @return 0 on success, 1 on missmatch
 */
int
expect_icmp (void *cls,
             uint16_t ifc,
             const void *msg,
             size_t msg_len,
             const void *cls1,
             ssize_t cls2,
             uint16_t cls3)
{
  char xbuf[msg_len];

  if (0 == ifc)
  {
    fprintf (stderr,
             "Received bogus text output\n");
    return 2;
  }
  if (msg_len <
      sizeof (struct EthernetHeader)
      + sizeof (struct IPv4Header) * 2
      + sizeof (struct IcmpHeader) + 8)
  {
    fprintf (stderr,
             "Message of %u bytes too small to be ICMP\n",
             (unsigned int) msg_len);
    return 1;
  }
  if (msg_len > cls2)
  {
    fprintf (stderr,
             "Message of %u bytes received too large to be our ICMP\n",
             (unsigned int) msg_len);
    return 1;
  }
  memcpy (xbuf,
          cls1,
          msg_len);
  /* patch up total_length */
  memcpy (&xbuf[sizeof (struct EthernetHeader) + offsetof (struct IPv4Header,
                                                           total_length)],
          &((char *) msg)[sizeof (struct EthernetHeader) + offsetof (struct
                                                                     IPv4Header,
                                                                     total_length)
          ],
          sizeof (uint16_t));
  /* patch up ICMP checksum (we won't bother to calculate it to check it here) */
  memcpy (&xbuf[sizeof (struct EthernetHeader)
                + sizeof (struct IPv4Header)
                + offsetof (struct IcmpHeader,
                            crc)],
          &((char *) msg)[sizeof (struct EthernetHeader)
                          + sizeof (struct IPv4Header)
                          + offsetof (struct IcmpHeader,
                                      crc)],
          sizeof (uint16_t));
  /* checksum will be patched up in expect_frame_ignore_fid() */
  return expect_frame_ignore_fid (NULL,
                                  ifc,
                                  msg,
                                  msg_len,
                                  xbuf,
                                  msg_len, /* compare shorter incoming msg! */
                                  cls3);
}


/**
 * We expect a frame with body @a cls1 of length @a cls2
 * on interface @e cls3.  However, the fragment ID is
 * random and should be ignored in the comparisson.
 *
 * @param cls closure
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls frame we expect
 * @param cls2 length of @a cls
 * @param cls3 interface we expect to receive from
 * @return 0 on success, 1 on missmatch
 */
int
expect_frame_ignore_fid (void *cls,
                         uint16_t ifc,
                         const void *msg,
                         size_t msg_len,
                         const void *cls1,
                         ssize_t cls2,
                         uint16_t cls3)
{
  const char *cmsg = msg;
  char buf[cls2];
  struct IPv4Header ip;
  unsigned int off;

  if (0 == ifc)
  {
    fprintf (stderr,
             "Received bogus text output\n");
    return 2;
  }
  if (cls2 < sizeof (struct EthernetHeader) + sizeof (struct IPv4Header))
    return 1;
  memcpy (buf,
          cls1,
          cls2);
  /* override expected identification and TTL with whatever we received */
  memcpy (&buf[sizeof (struct EthernetHeader) + offsetof (struct IPv4Header,
                                                          identification)],
          &cmsg[sizeof (struct EthernetHeader) + offsetof (struct IPv4Header,
                                                           identification)],
          sizeof (uint16_t));
  memcpy (&buf[sizeof (struct EthernetHeader) + offsetof (struct IPv4Header,
                                                          ttl)],
          &cmsg[sizeof (struct EthernetHeader) + offsetof (struct IPv4Header,
                                                           ttl)],
          sizeof (uint8_t));
  /* patch up checksum */
  memcpy (&ip,
          &buf[sizeof (struct EthernetHeader)],
          sizeof (ip));
  calc_ipv4_checksum (&ip);
  memcpy (&buf[sizeof (struct EthernetHeader)],
          &ip,
          sizeof (ip));
  /* now we can compare! */
  if ( (cls3 == ifc) &&
       (msg_len == cls2) &&
       (0 == memcmp (msg,
                     buf,
                     cls2)) )
    return 0;

  off = UINT_MAX;
  fprintf (stderr,
           "BAD: ");
  if ( (cls3 == ifc) &&
       (msg_len == cls2) )
  {
    const uint8_t *b1 = msg;
    const uint8_t *b2 = cls1;

    for (unsigned int i = 0; i<msg_len; i++)
    {
      fprintf (stderr,
               "%c",
               b1[i] != b2[i] ? 'X' : '.');
      if ( (b1[i] != b2[i]) &&
           (UINT_MAX == off) )
        off = i;
    }
  }
  fprintf (stderr,
           "\n");
#if DEBUG
  fprintf (stderr,
           "Received unexpected %u byte frame (%d/%d/%u) on interface %u\n",
           (unsigned int) msg_len,
           (cls3 == ifc),
           (msg_len == cls2),
           off,
           ifc);
#endif
  return 1;
}


/**
 * Send message.
 *
 * @param type message type to use (0 = control, other: interface)
 * @param msg payload to send
 * @param msg_len number of bytes in @a msg
 */
void
tsend (uint16_t type,
       const void *msg,
       size_t msg_len)
{
  struct GLAB_MessageHeader hdr;

  if (msg_len > UINT16_MAX - sizeof (hdr))
    abort ();
  hdr.type = htons (type);
  hdr.size = htons (sizeof (hdr) + msg_len);
  write_all (child_stdin,
             &hdr,
             sizeof (hdr));
  write_all (child_stdin,
             msg,
             msg_len);
}


/**
 * Receive message.
 *
 * @param skip_until_match number of messages we may skip until
 *        the desired message must appear
 * @param recv function to call with the message we got
 * @param recv_cls closure for @a recv
 * @param recv_cls2 additional length argument for @a recv
 * @return 0 on success
 */
int
trecv (unsigned int skip_until_match,
       Receiver recv,
       void *recv_cls,
       const void *recv_cls1,
       ssize_t recv_cls2,
       uint16_t recv_cls3)
{
  time_t etime;
  int ret;

  etime = time (NULL) + 3; /* wait at MOST 2-3 s (rounding!) */
  while (UINT_MAX != skip_until_match--)
  {
    struct GLAB_MessageHeader hdr;
    uint16_t size;

    memcpy (&hdr,
            child_buf,
            sizeof (hdr));
    while ( (child_buf_pos < sizeof (hdr)) ||
            (child_buf_pos < ntohs (hdr.size)) )
    {
      struct timeval to;
      fd_set rfd;
      ssize_t iret;

      FD_ZERO (&rfd);
      FD_SET (child_stdout,
              &rfd);
      to.tv_sec = etime - time (NULL);
      to.tv_usec = 0;
      ret = select (child_stdout + 1,
                    &rfd,
                    NULL,
                    NULL,
                    &to);
      if (0 >= ret)
      {
        fprintf (stderr,
                 "Failed to receive frame (select returned %d)\n",
                 ret);
        return 1;       /* timeout or error */
      }
      if (! FD_ISSET (child_stdout,
                      &rfd))
        abort (); /* how could this be!? */
      iret = read (child_stdout,
                   &child_buf[child_buf_pos],
                   sizeof (child_buf) - child_buf_pos);
      if (0 >= iret)
      {
        fprintf (stderr,
                 "Failed to receive frame (read returned %d)\n",
                 (int) iret);
        return 1;
      }
      child_buf_pos += iret;
      memcpy (&hdr,
              child_buf,
              sizeof (hdr));
    }
    size = ntohs (hdr.size);
    ret = recv (recv_cls,
                ntohs (hdr.type),
                &child_buf[sizeof (hdr)],
                size - sizeof (hdr),
                recv_cls1,
                recv_cls2,
                recv_cls3);
    memmove (child_buf,
             &child_buf[size],
             child_buf_pos - size);
    child_buf_pos -= size;
    if (2 == ret)
      skip_until_match++;
    if (0 == ret)
      return 0;
  }
  fprintf (stderr,
           "Failed to receive frame (attempts exhausted)\n");
  return 1;
}


/**
 * Check that we are receiving NOTHING (for a few seconds).
 *
 * @return 0 on success
 */
int
expect_silence ()
{
  struct GLAB_MessageHeader hdr;
  uint16_t size;
  time_t etime;
  int ret;

  etime = time (NULL) + 3; /* wait at MOST 2-3 s (rounding!) */
  memcpy (&hdr,
          child_buf,
          sizeof (hdr));
  while ( (child_buf_pos >= sizeof (hdr)) &&
          (child_buf_pos >= ntohs (hdr.size)) &&
          (0 == ntohs (hdr.type)) )
  {
    fprintf (stderr,
             "Received bogus text output instead of silence\n");
    size = ntohs (hdr.size);
    memmove (child_buf,
             &child_buf[size],
             child_buf_pos - size);
    child_buf_pos -= size;
    memcpy (&hdr,
            child_buf,
            sizeof (hdr));
  }
  while ( (child_buf_pos < sizeof (hdr)) ||
          (child_buf_pos < ntohs (hdr.size)) )
  {
    struct timeval to;
    fd_set rfd;
    ssize_t iret;

    FD_ZERO (&rfd);
    FD_SET (child_stdout,
            &rfd);
    to.tv_sec = etime - time (NULL);
    to.tv_usec = 0;
    ret = select (child_stdout + 1,
                  &rfd,
                  NULL,
                  NULL,
                  &to);
    if (0 == ret)
      return 0; /* timeout, good! */
    if (-1 == ret)
      return 1;
    if (! FD_ISSET (child_stdout,
                    &rfd))
      abort (); /* how could this be!? */
    iret = read (child_stdout,
                 &child_buf[child_buf_pos],
                 sizeof (child_buf) - child_buf_pos);
    if (0 >= iret)
      return 1;
    child_buf_pos += iret;
    memcpy (&hdr,
            child_buf,
            sizeof (hdr));
    while ( (child_buf_pos >= sizeof (hdr)) &&
            (child_buf_pos >= ntohs (hdr.size)) &&
            (0 == ntohs (hdr.type)) )
    {
      fprintf (stderr,
               "Received bogus text output instead of silence\n");
      size = ntohs (hdr.size);
      memmove (child_buf,
               &child_buf[size],
               child_buf_pos - size);
      child_buf_pos -= size;
      memcpy (&hdr,
              child_buf,
              sizeof (hdr));
    }
  }
  fprintf (stderr,
           "Received message to %u when we expected silence (%u/%u)!\n",
           (unsigned int) ntohs (hdr.type),
           (unsigned int) ntohs (hdr.size),
           (unsigned int) child_buf_pos);
  size = ntohs (hdr.size);
  memmove (child_buf,
           &child_buf[size],
           child_buf_pos - size);
  child_buf_pos -= size;
  return 1; /* we got something! */
}


/**
 * Start the actual test.
 *
 * @param cmd test commands to run
 */
static int
run (struct Command *cmd)
{
  for (unsigned int i = 0; NULL != cmd[i].fun; i++)
  {
    int ret;

#if DEBUG
    fprintf (stderr,
             "Running CMD `%s'\n",
             cmd[i].label);
#endif
    if (0 != (ret = cmd[i].fun ()))
      return ret;
  }
  return 0;
}


/**
 * Start test and pass traffic from/to child process.
 *
 * @param argc number of arguments in @a argv
 * @param argv 0: binary name (program to test)
 *             1..n: network interface specs (e.g. eth0)
 * @return 0 on success
 */
int
meta (struct Command *cmd,
      int argc,
      char **argv)
{
  struct MacAddress ifcs[argc - 1];
  int ret;
  pid_t chld;

  (void) print;
  if (SIG_ERR ==
      signal (SIGPIPE,
              SIG_IGN))
  {
    fprintf (stderr,
             "Failed to protect against SIGPIPE: %s\n",
             strerror (errno));
    /* no exit, we might as well die with SIGPIPE should it ever happen */
  }
  for (unsigned int i = 0; i<argc - 1; i++)
    for (unsigned int j = 0; j<MAC_ADDR_SIZE; j++)
      ifcs[i].mac[j] = (0xFE & random ());
  /* avoids multicast */
  gifcs = ifcs;
  num_ifcs = argc - 1;
  /* Launch child process */
  {
    int cin[2];
    int cout[2];

    if (0 != pipe (cin))
    {
      perror ("pipe");
      return 1;
    }
    if (0 != pipe (cout))
    {
      perror ("pipe");
      return 1;
    }
    chld = fork ();
    if (-1 == chld)
    {
      perror ("fork");
      return 1;
    }
    if (0 == chld)
    {
      close (STDIN_FILENO);
      close (STDOUT_FILENO);
      close (cin[1]);
      close (cout[0]);
      if (-1 == dup2 (cin[0],
                      STDIN_FILENO))
      {
        perror ("dup2");
        exit (1);
      }
      if (-1 == dup2 (cout[1],
                      STDOUT_FILENO))
      {
        perror ("dup2");
        exit (1);
      }
      execvp (argv[0],
              argv);
      fprintf (stderr,
               "Failed to run binary `%s'\n",
               argv[0]);
      exit (1);
    }
    close (cin[0]);
    close (cout[1]);
    child_stdin = cin[1];
    child_stdout = cout[0];
  } /* end launch child */

  /* send primary control message */
  {
    struct GLAB_MessageHeader gh;
    char *mbuf;
    size_t size;

    size = sizeof (struct GLAB_MessageHeader) + (argc - 1) * MAC_ADDR_SIZE;
    mbuf = malloc (size);
    if (NULL == mbuf)
      abort ();
    gh.size = htons (size);
    gh.type = htons (0);
    memcpy (mbuf,
            &gh,
            sizeof (gh));
    for (unsigned int i = 1; i<argc; i++)
      memcpy (&mbuf[sizeof (struct GLAB_MessageHeader) + (i - 1)
                    * MAC_ADDR_SIZE],
              &ifcs[i - 1],
              MAC_ADDR_SIZE);
    if (size !=
        write (child_stdin,
               mbuf,
               size))
    {
      fprintf (stderr,
               "Failed to send my MACs to application: %s",
               strerror (errno));
      free (mbuf);
      ret = 4;
      goto cleanup;
    }
    free (mbuf);
  }
  ret = run (cmd);
cleanup:
  kill (chld,
        SIGKILL);
  close (child_stdin);
  close (child_stdout);
  return ret;
}


/* end of harness */
