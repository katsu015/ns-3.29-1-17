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

#include "bhattackdsr-network-queue.h"
#include "ns3/test.h"
#include <map>
#include <algorithm>
#include <functional>
#include "ns3/log.h"
#include "ns3/ipv4-route.h"
#include "ns3/socket.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BhattackdsrNetworkQueue");

namespace bhattackdsr {

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrNetworkQueue);

TypeId
BhattackdsrNetworkQueue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrNetworkQueue")
    .SetParent<Object> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrNetworkQueue>  ()
  ;
  return tid;
}

BhattackdsrNetworkQueue::BhattackdsrNetworkQueue (uint32_t maxLen, Time maxDelay)
  : m_size (0),
    m_maxSize (maxLen),
    m_maxDelay (maxDelay)
{
  NS_LOG_FUNCTION (this);
}

BhattackdsrNetworkQueue::BhattackdsrNetworkQueue () : m_size (0)
{
  NS_LOG_FUNCTION (this);
}

BhattackdsrNetworkQueue::~BhattackdsrNetworkQueue ()
{
  NS_LOG_FUNCTION (this);
  Flush ();
}

void
BhattackdsrNetworkQueue::SetMaxNetworkSize (uint32_t maxSize)
{
  m_maxSize = maxSize;
}

void
BhattackdsrNetworkQueue::SetMaxNetworkDelay (Time delay)
{
  m_maxDelay = delay;
}

uint32_t
BhattackdsrNetworkQueue::GetMaxNetworkSize (void) const
{
  return m_maxSize;
}

Time
BhattackdsrNetworkQueue::GetMaxNetworkDelay (void) const
{
  return m_maxDelay;
}

bool
BhattackdsrNetworkQueue::FindPacketWithNexthop (Ipv4Address nextHop, BhattackdsrNetworkQueueEntry & entry)
{
  Cleanup ();
  for (std::vector<BhattackdsrNetworkQueueEntry>::iterator i = m_bhattackdsrNetworkQueue.begin (); i != m_bhattackdsrNetworkQueue.end (); ++i)
    {
      if (i->GetNextHopAddress () == nextHop)
        {
          entry = *i;
          i = m_bhattackdsrNetworkQueue.erase (i);
          return true;
        }
    }
  return false;
}

bool
BhattackdsrNetworkQueue::Find (Ipv4Address nextHop)
{
  Cleanup ();
  for (std::vector<BhattackdsrNetworkQueueEntry>::iterator i = m_bhattackdsrNetworkQueue.begin (); i != m_bhattackdsrNetworkQueue.end (); ++i)
    {
      if (i->GetNextHopAddress () == nextHop)
        {
          return true;
        }
    }
  return false;
}

bool
BhattackdsrNetworkQueue::Enqueue (BhattackdsrNetworkQueueEntry & entry)
{
  NS_LOG_FUNCTION (this << m_size << m_maxSize);
  if (m_size >= m_maxSize)
    {
      return false;
    }
  Time now = Simulator::Now ();
  entry.SetInsertedTimeStamp (now);
  m_bhattackdsrNetworkQueue.push_back (entry);
  m_size++;
  NS_LOG_LOGIC ("The network queue size is " << m_size);
  return true;
}

bool
BhattackdsrNetworkQueue::Dequeue (BhattackdsrNetworkQueueEntry & entry)
{
  NS_LOG_FUNCTION (this);
  Cleanup ();
  std::vector<BhattackdsrNetworkQueueEntry>::iterator i = m_bhattackdsrNetworkQueue.begin ();
  if (i == m_bhattackdsrNetworkQueue.end ())
    {
      // no elements in array
      NS_LOG_LOGIC ("No queued packet in the network queue");
      return false;
    }
  entry = *i;
  m_bhattackdsrNetworkQueue.erase (i);
  m_size--;
  return true;
}

void
BhattackdsrNetworkQueue::Cleanup (void)
{
  NS_LOG_FUNCTION (this);
  if (m_bhattackdsrNetworkQueue.empty ())
    {
      return;
    }

  Time now = Simulator::Now ();
  uint32_t n = 0;
  for (std::vector<BhattackdsrNetworkQueueEntry>::iterator i = m_bhattackdsrNetworkQueue.begin (); i != m_bhattackdsrNetworkQueue.end (); )
    {
      if (i->GetInsertedTimeStamp () + m_maxDelay > now)
        {
          i++;
        }
      else
        {
          NS_LOG_LOGIC ("Outdated packet");
          i = m_bhattackdsrNetworkQueue.erase (i);
          n++;
        }
    }
  m_size -= n;
}

uint32_t
BhattackdsrNetworkQueue::GetSize ()
{
  NS_LOG_FUNCTION (this);
  return m_size;
}

void
BhattackdsrNetworkQueue::Flush (void)
{
  NS_LOG_FUNCTION (this);
  m_bhattackdsrNetworkQueue.erase (m_bhattackdsrNetworkQueue.begin (), m_bhattackdsrNetworkQueue.end ());
  m_size = 0;
}

}  // namespace bhattackdsr
}  // namespace ns3
