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

#ifndef DSR_MAIN_HELPER_H
#define DSR_MAIN_HELPER_H

#include "ns3/object-factory.h"
#include "ns3/node.h"
#include "ns3/node-container.h"
#include "ns3/rushattackdsr-routing.h"
#include "ns3/rushattackdsr-helper.h"

namespace ns3 {

/**
 * \ingroup rushattackdsr
 *
 * \brief Helper class that adds DSR routing to nodes.
 */
class RushattackdsrMainHelper
{
public:
  /**
   * Create an RushattackdsrMainHelper that makes life easier for people who want to install
   * DSR routing to nodes.
   */
  RushattackdsrMainHelper ();
  ~RushattackdsrMainHelper ();
  /**
   * \brief Construct an RushattackdsrMainHelper from another previously initialized instance
   * (Copy Constructor).
   */
  RushattackdsrMainHelper (const RushattackdsrMainHelper &);
  /**
   * Install routing to the nodes
   * \param rushattackdsrHelper The DSR helper class
   * \param nodes the collection of nodes
   */
  void Install (RushattackdsrHelper &rushattackdsrHelper, NodeContainer nodes);
  /**
   * Set the helper class
   * \param rushattackdsrHelper the DSR helper class
   */
  void SetRushattackdsrHelper (RushattackdsrHelper &rushattackdsrHelper);

private:
  /**
   * Install routing to a node
   * \param node the node to install DSR routing
   */
  void Install (Ptr<Node> node);
  /**
   * \brief Assignment operator declared private and not implemented to disallow
   * assignment and prevent the compiler from happily inserting its own.
   * \param o source object to assign
   * \return RushattackdsrHelper object
  */
  RushattackdsrMainHelper &operator = (const RushattackdsrMainHelper &o);
  const RushattackdsrHelper *m_rushattackdsrHelper; ///< helper class
};

} // namespace ns3

#endif /* DSR_MAIN_HELPER_H */
