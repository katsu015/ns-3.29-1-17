/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Yufei Cheng
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Yufei Cheng   <yfcheng@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#include "bhattackdsr-passive-buff.h"
#include <algorithm>
#include <functional>
#include "ns3/ipv4-route.h"
#include "ns3/socket.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BhattackdsrPassiveBuffer");

namespace bhattackdsr {

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrPassiveBuffer);

TypeId BhattackdsrPassiveBuffer::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrPassiveBuffer")
    .SetParent<Object> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrPassiveBuffer> ()
  ;
  return tid;
}

BhattackdsrPassiveBuffer::BhattackdsrPassiveBuffer ()
{
}

BhattackdsrPassiveBuffer::~BhattackdsrPassiveBuffer ()
{
}

uint32_t
BhattackdsrPassiveBuffer::GetSize ()
{
  Purge ();
  return m_passiveBuffer.size ();
}

bool
BhattackdsrPassiveBuffer::Enqueue (BhattackdsrPassiveBuffEntry & entry)
{
  Purge ();
  for (std::vector<BhattackdsrPassiveBuffEntry>::const_iterator i = m_passiveBuffer.begin (); i
       != m_passiveBuffer.end (); ++i)
    {
//      NS_LOG_INFO ("packet id " << i->GetPacket ()->GetUid () << " " << entry.GetPacket ()->GetUid () << " source " << i->GetSource () << " " << entry.GetSource ()
//                                     << " dst " << i->GetDestination () << " " << entry.GetDestination () << " identification " << i->GetIdentification () << " "
//                                     << entry.GetIdentification () << " fragment " << i->GetFragmentOffset () << " " << entry.GetFragmentOffset ()
//                                     << " segLeft " << i->GetSegsLeft () << " " << entry.GetSegsLeft ());

      if ((i->GetPacket ()->GetUid () == entry.GetPacket ()->GetUid ()) && (i->GetSource () == entry.GetSource ()) && (i->GetNextHop () == entry.GetNextHop ())
          && (i->GetDestination () == entry.GetDestination ()) && (i->GetIdentification () == entry.GetIdentification ()) && (i->GetFragmentOffset () == entry.GetFragmentOffset ())
          && (i->GetSegsLeft () == entry.GetSegsLeft () + 1))
        {
          return false;
        }
    }

  entry.SetExpireTime (m_passiveBufferTimeout);     // Initialize the send buffer timeout
  /*
   * Drop the most aged packet when buffer reaches to max
   */
  if (m_passiveBuffer.size () >= m_maxLen)
    {
      Drop (m_passiveBuffer.front (), "Drop the most aged packet");         // Drop the most aged packet
      m_passiveBuffer.erase (m_passiveBuffer.begin ());
    }
  // enqueue the entry
  m_passiveBuffer.push_back (entry);
  return true;
}

bool
BhattackdsrPassiveBuffer::AllEqual (BhattackdsrPassiveBuffEntry & entry)
{
  for (std::vector<BhattackdsrPassiveBuffEntry>::iterator i = m_passiveBuffer.begin (); i
       != m_passiveBuffer.end (); ++i)
    {
//      NS_LOG_INFO ("packet id " << i->GetPacket ()->GetUid () << " " << entry.GetPacket ()->GetUid () << " source " << i->GetSource () << " " << entry.GetSource ()
//                                     << " dst " << i->GetDestination () << " " << entry.GetDestination () << " identification " << i->GetIdentification () << " "
//                                     << entry.GetIdentification () << " fragment " << i->GetFragmentOffset () << " " << entry.GetFragmentOffset ()
//                                     << " segLeft " << (uint32_t) i->GetSegsLeft () << " " << (uint32_t) entry.GetSegsLeft ());

      if ((i->GetPacket ()->GetUid () == entry.GetPacket ()->GetUid ()) && (i->GetSource () == entry.GetSource ()) && (i->GetNextHop () == entry.GetNextHop ())
          && (i->GetDestination () == entry.GetDestination ()) && (i->GetIdentification () == entry.GetIdentification ()) && (i->GetFragmentOffset () == entry.GetFragmentOffset ())
          && (i->GetSegsLeft () == entry.GetSegsLeft () + 1))
        {
          i = m_passiveBuffer.erase (i);   // Erase the same maintain buffer entry for the received packet
          return true;
        }
    }
  return false;
}

bool
BhattackdsrPassiveBuffer::Dequeue (Ipv4Address dst, BhattackdsrPassiveBuffEntry & entry)
{
  Purge ();
  /*
   * Dequeue the entry with destination address dst
   */
  for (std::vector<BhattackdsrPassiveBuffEntry>::iterator i = m_passiveBuffer.begin (); i != m_passiveBuffer.end (); ++i)
    {
      if (i->GetDestination () == dst)
        {
          entry = *i;
          i = m_passiveBuffer.erase (i);
          NS_LOG_DEBUG ("Packet size while dequeuing " << entry.GetPacket ()->GetSize ());
          return true;
        }
    }
  return false;
}

bool
BhattackdsrPassiveBuffer::Find (Ipv4Address dst)
{
  /*
   * Make sure if the send buffer contains entry with certain dst
   */
  for (std::vector<BhattackdsrPassiveBuffEntry>::const_iterator i = m_passiveBuffer.begin (); i
       != m_passiveBuffer.end (); ++i)
    {
      if (i->GetDestination () == dst)
        {
          NS_LOG_DEBUG ("Found the packet");
          return true;
        }
    }
  return false;
}

/// IsExpired structure
struct IsExpired
{
  /**
   * Check for an expired entry
   * \param e passive buffer entry
   * \return true if equal
   */
  bool
  operator() (BhattackdsrPassiveBuffEntry const & e) const
  {
    // NS_LOG_DEBUG("Expire time for packet in req queue: "<<e.GetExpireTime ());
    return (e.GetExpireTime () < Seconds (0));
  }
};

void
BhattackdsrPassiveBuffer::Purge ()
{
  /*
   * バッファをパージして期限切れのエントリを削除します
   */
  NS_LOG_DEBUG ("The passive buffer size " << m_passiveBuffer.size ());
  IsExpired pred;
  for (std::vector<BhattackdsrPassiveBuffEntry>::iterator i = m_passiveBuffer.begin (); i
       != m_passiveBuffer.end (); ++i)
    {
      if (pred (*i))
        {
          NS_LOG_DEBUG ("Dropping Queue Packets");
          Drop (*i, "Drop out-dated packet ");
        }
    }
  m_passiveBuffer.erase (std::remove_if (m_passiveBuffer.begin (), m_passiveBuffer.end (), pred),
                         m_passiveBuffer.end ());
}

void
BhattackdsrPassiveBuffer::Drop (BhattackdsrPassiveBuffEntry en, std::string reason)
{
  NS_LOG_LOGIC (reason << en.GetPacket ()->GetUid () << " " << en.GetDestination ());
//  en.GetErrorCallback () (en.GetPacket (), en.GetDestination (),
//     Socket::ERROR_NOROUTETOHOST);
  return;
}

void
BhattackdsrPassiveBuffer::DropLink (BhattackdsrPassiveBuffEntry en, std::string reason)
{
  NS_LOG_LOGIC (reason << en.GetPacket ()->GetUid () << " " << en.GetSource () << " " << en.GetNextHop ());
//  en.GetErrorCallback () (en.GetPacket (), en.GetDestination (),
//     Socket::ERROR_NOROUTETOHOST);
  return;
}
}  // namespace bhattackdsr
}  // namespace ns3
