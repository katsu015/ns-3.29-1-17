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

#include "bhattackdsr-main-helper.h"
#include "ns3/bhattackdsr-helper.h"
#include "ns3/bhattackdsr-routing.h"
#include "ns3/bhattackdsr-rcache.h"
#include "ns3/bhattackdsr-rreq-table.h"
#include "ns3/node-list.h"
#include "ns3/names.h"
#include "ns3/log.h"
#include "ns3/ptr.h"
#include "ns3/node.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BhattackdsrMainHelper");

BhattackdsrMainHelper::BhattackdsrMainHelper ()
  : m_bhattackdsrHelper (0)
{
  NS_LOG_FUNCTION (this);
}

BhattackdsrMainHelper::BhattackdsrMainHelper (const BhattackdsrMainHelper &o)
{
  NS_LOG_FUNCTION (this);
  m_bhattackdsrHelper = o.m_bhattackdsrHelper->Copy ();
}

BhattackdsrMainHelper::~BhattackdsrMainHelper ()
{
  NS_LOG_FUNCTION (this);
  delete m_bhattackdsrHelper;
}

BhattackdsrMainHelper &
BhattackdsrMainHelper::operator = (const BhattackdsrMainHelper &o)
{
  if (this == &o)
    {
      return *this;
    }
  m_bhattackdsrHelper = o.m_bhattackdsrHelper->Copy ();
  return *this;
}

void
BhattackdsrMainHelper::Install (BhattackdsrHelper &bhattackdsrHelper, NodeContainer nodes)
{
  NS_LOG_DEBUG ("Passed node container");
  delete m_bhattackdsrHelper;
  m_bhattackdsrHelper = bhattackdsrHelper.Copy ();
  for (NodeContainer::Iterator i = nodes.Begin (); i != nodes.End (); ++i)
    {
      Install (*i);
    }
}

void
BhattackdsrMainHelper::Install (Ptr<Node> node)
{
  NS_LOG_FUNCTION (node);
  Ptr<ns3::bhattackdsr::BhattackdsrRouting> bhattackdsr = m_bhattackdsrHelper->Create (node);
//  Ptr<ns3::bhattackdsr::RouteCache> routeCache = CreateObject<ns3::bhattackdsr::RouteCache> ();
//  Ptr<ns3::bhattackdsr::RreqTable> rreqTable = CreateObject<ns3::bhattackdsr::RreqTable> ();
//  bhattackdsr->SetRouteCache (routeCache);
//  bhattackdsr->SetRequestTable (rreqTable);
  bhattackdsr->SetNode (node);
//  node->AggregateObject (routeCache);
//  node->AggregateObject (rreqTable);
}

void
BhattackdsrMainHelper::SetBhattackdsrHelper (BhattackdsrHelper &bhattackdsrHelper)
{
  NS_LOG_FUNCTION (this);
  delete m_bhattackdsrHelper;
  m_bhattackdsrHelper = bhattackdsrHelper.Copy ();
}

} // namespace ns3
