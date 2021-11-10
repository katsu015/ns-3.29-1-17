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

#include <vector>
#include "ns3/ptr.h"
#include "ns3/boolean.h"
#include "ns3/test.h"
#include "ns3/ipv4-route.h"
#include "ns3/mesh-helper.h"
#include "ns3/simulator.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/ipv4-address-helper.h"

#include "ns3/bhattackdsr-fs-header.h"
#include "ns3/bhattackdsr-option-header.h"
#include "ns3/bhattackdsr-rreq-table.h"
#include "ns3/bhattackdsr-rcache.h"
#include "ns3/bhattackdsr-rsendbuff.h"
#include "ns3/bhattackdsr-main-helper.h"
#include "ns3/bhattackdsr-helper.h"

using namespace ns3;
using namespace bhattackdsr;

// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr
 * \defgroup bhattackdsr-test DSR routing module tests
 */


/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrFsHeaderTest
 * \brief Unit test for DSR Fixed Size Header
 */
class BhattackdsrFsHeaderTest : public TestCase
{
public:
  BhattackdsrFsHeaderTest ();
  ~BhattackdsrFsHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrFsHeaderTest::BhattackdsrFsHeaderTest ()
  : TestCase ("DSR Fixed size Header")
{
}
BhattackdsrFsHeaderTest::~BhattackdsrFsHeaderTest ()
{
}
void
BhattackdsrFsHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrRoutingHeader header;
  bhattackdsr::BhattackdsrOptionRreqHeader rreqHeader;
  header.AddBhattackdsrOption (rreqHeader); // has an alignment of 4n+0

  NS_TEST_EXPECT_MSG_EQ (header.GetSerializedSize () % 2, 0, "length of routing header is not a multiple of 4");
  Buffer buf;
  buf.AddAtStart (header.GetSerializedSize ());
  header.Serialize (buf.Begin ());

  const uint8_t* data = buf.PeekData ();
  NS_TEST_EXPECT_MSG_EQ (*(data + 8), rreqHeader.GetType (), "expect the rreqHeader after fixed size header");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrRreqHeaderTest
 * \brief Unit test for RREQ
 */
class BhattackdsrRreqHeaderTest : public TestCase
{
public:
  BhattackdsrRreqHeaderTest ();
  ~BhattackdsrRreqHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrRreqHeaderTest::BhattackdsrRreqHeaderTest ()
  : TestCase ("DSR RREQ")
{
}
BhattackdsrRreqHeaderTest::~BhattackdsrRreqHeaderTest ()
{
}
void
BhattackdsrRreqHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionRreqHeader h;
  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));

  h.SetTarget (Ipv4Address ("1.1.1.3"));
  NS_TEST_EXPECT_MSG_EQ (h.GetTarget (), Ipv4Address ("1.1.1.3"), "trivial");
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");
  h.SetId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  bhattackdsr::BhattackdsrOptionRreqHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 20, "Total RREP is 20 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrRrepHeaderTest
 * \brief Unit test for RREP
 */
class BhattackdsrRrepHeaderTest : public TestCase
{
public:
  BhattackdsrRrepHeaderTest ();
  ~BhattackdsrRrepHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrRrepHeaderTest::BhattackdsrRrepHeaderTest ()
  : TestCase ("DSR RREP")
{
}
BhattackdsrRrepHeaderTest::~BhattackdsrRrepHeaderTest ()
{
}
void
BhattackdsrRrepHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionRrepHeader h;

  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  bhattackdsr::BhattackdsrOptionRrepHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 16, "Total RREP is 16 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrSRHeaderTest
 * \brief Unit test for Source Route
 */
class BhattackdsrSRHeaderTest : public TestCase
{
public:
  BhattackdsrSRHeaderTest ();
  ~BhattackdsrSRHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrSRHeaderTest::BhattackdsrSRHeaderTest ()
  : TestCase ("DSR Source Route")
{
}
BhattackdsrSRHeaderTest::~BhattackdsrSRHeaderTest ()
{
}
void
BhattackdsrSRHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionSRHeader h;
  std::vector<Ipv4Address> nodeList;
  nodeList.push_back (Ipv4Address ("1.1.1.0"));
  nodeList.push_back (Ipv4Address ("1.1.1.1"));
  nodeList.push_back (Ipv4Address ("1.1.1.2"));
  h.SetNodesAddress (nodeList);
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (0), Ipv4Address ("1.1.1.0"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (1), Ipv4Address ("1.1.1.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (h.GetNodeAddress (2), Ipv4Address ("1.1.1.2"), "trivial");

  h.SetSalvage (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetSalvage (), 1, "trivial");
  h.SetSegmentsLeft (2);
  NS_TEST_EXPECT_MSG_EQ (h.GetSegmentsLeft (), 2, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  bhattackdsr::BhattackdsrOptionSRHeader h2;
  h2.SetNumberAddress (3);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 16, "Total RREP is 16 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrRerrHeaderTest
 * \brief Unit test for RERR
 */
class BhattackdsrRerrHeaderTest : public TestCase
{
public:
  BhattackdsrRerrHeaderTest ();
  ~BhattackdsrRerrHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrRerrHeaderTest::BhattackdsrRerrHeaderTest ()
  : TestCase ("DSR RERR")
{
}
BhattackdsrRerrHeaderTest::~BhattackdsrRerrHeaderTest ()
{
}
void
BhattackdsrRerrHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionRerrUnreachHeader h;
  h.SetErrorSrc (Ipv4Address ("1.1.1.0"));
  NS_TEST_EXPECT_MSG_EQ (h.GetErrorSrc (), Ipv4Address ("1.1.1.0"), "trivial");
  h.SetErrorDst (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (h.GetErrorDst (), Ipv4Address ("1.1.1.1"), "trivial");
  h.SetSalvage (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetSalvage (), 1, "trivial");
  h.SetUnreachNode (Ipv4Address ("1.1.1.2"));
  NS_TEST_EXPECT_MSG_EQ (h.GetUnreachNode (), Ipv4Address ("1.1.1.2"), "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  bhattackdsr::BhattackdsrOptionRerrUnreachHeader h2;
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 20, "Total RREP is 20 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrAckReqHeaderTest
 * \brief Unit test for ACK-REQ
 */
class BhattackdsrAckReqHeaderTest : public TestCase
{
public:
  BhattackdsrAckReqHeaderTest ();
  ~BhattackdsrAckReqHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrAckReqHeaderTest::BhattackdsrAckReqHeaderTest ()
  : TestCase ("DSR Ack Req")
{
}
BhattackdsrAckReqHeaderTest::~BhattackdsrAckReqHeaderTest ()
{
}
void
BhattackdsrAckReqHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionAckReqHeader h;

  h.SetAckId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetAckId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  p->AddHeader (header);
  bhattackdsr::BhattackdsrOptionAckReqHeader h2;
  p->RemoveAtStart (8);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 4, "Total RREP is 4 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrAckHeaderTest
 * \brief Unit test for ACK
 */
class BhattackdsrAckHeaderTest : public TestCase
{
public:
  BhattackdsrAckHeaderTest ();
  ~BhattackdsrAckHeaderTest ();
  virtual void
  DoRun (void);
};
BhattackdsrAckHeaderTest::BhattackdsrAckHeaderTest ()
  : TestCase ("DSR ACK")
{
}
BhattackdsrAckHeaderTest::~BhattackdsrAckHeaderTest ()
{
}
void
BhattackdsrAckHeaderTest::DoRun ()
{
  bhattackdsr::BhattackdsrOptionAckHeader h;

  h.SetRealSrc (Ipv4Address ("1.1.1.0"));
  NS_TEST_EXPECT_MSG_EQ (h.GetRealSrc (), Ipv4Address ("1.1.1.0"), "trivial");
  h.SetRealDst (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (h.GetRealDst (), Ipv4Address ("1.1.1.1"), "trivial");
  h.SetAckId (1);
  NS_TEST_EXPECT_MSG_EQ (h.GetAckId (), 1, "trivial");

  Ptr<Packet> p = Create<Packet> ();
  bhattackdsr::BhattackdsrRoutingHeader header;
  header.AddBhattackdsrOption (h);
  p->AddHeader (header);
  p->RemoveAtStart (8);
  p->AddHeader (header);
  bhattackdsr::BhattackdsrOptionAckHeader h2;
  p->RemoveAtStart (8);
  uint32_t bytes = p->RemoveHeader (h2);
  NS_TEST_EXPECT_MSG_EQ (bytes, 12, "Total RREP is 12 bytes long");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrCacheEntryTest
 * \brief Unit test for DSR route cache entry
 */
class BhattackdsrCacheEntryTest : public TestCase
{
public:
  BhattackdsrCacheEntryTest ();
  ~BhattackdsrCacheEntryTest ();
  virtual void
  DoRun (void);
};
BhattackdsrCacheEntryTest::BhattackdsrCacheEntryTest ()
  : TestCase ("DSR ACK")
{
}
BhattackdsrCacheEntryTest::~BhattackdsrCacheEntryTest ()
{
}
void
BhattackdsrCacheEntryTest::DoRun ()
{
  Ptr<bhattackdsr::BhattackdsrRouteCache> rcache = CreateObject<bhattackdsr::BhattackdsrRouteCache> ();
  std::vector<Ipv4Address> ip;
  ip.push_back (Ipv4Address ("0.0.0.0"));
  ip.push_back (Ipv4Address ("0.0.0.1"));
  Ipv4Address dst = Ipv4Address ("0.0.0.1");
  bhattackdsr::BhattackdsrRouteCacheEntry entry (ip, dst, Seconds (1));
  NS_TEST_EXPECT_MSG_EQ (entry.GetVector ().size (), 2, "trivial");
  NS_TEST_EXPECT_MSG_EQ (entry.GetDestination (), Ipv4Address ("0.0.0.1"), "trivial");
  NS_TEST_EXPECT_MSG_EQ (entry.GetExpireTime (), Seconds (1), "trivial");

  entry.SetExpireTime (Seconds (3));
  NS_TEST_EXPECT_MSG_EQ (entry.GetExpireTime (), Seconds (3), "trivial");
  entry.SetDestination (Ipv4Address ("1.1.1.1"));
  NS_TEST_EXPECT_MSG_EQ (entry.GetDestination (), Ipv4Address ("1.1.1.1"), "trivial");
  ip.push_back (Ipv4Address ("0.0.0.2"));
  entry.SetVector (ip);
  NS_TEST_EXPECT_MSG_EQ (entry.GetVector ().size (), 3, "trivial");

  NS_TEST_EXPECT_MSG_EQ (rcache->AddRoute (entry), true, "trivial");

  std::vector<Ipv4Address> ip2;
  ip2.push_back (Ipv4Address ("1.1.1.0"));
  ip2.push_back (Ipv4Address ("1.1.1.1"));
  Ipv4Address dst2 = Ipv4Address ("1.1.1.1");
  bhattackdsr::BhattackdsrRouteCacheEntry entry2 (ip2, dst2, Seconds (2));
  bhattackdsr::BhattackdsrRouteCacheEntry newEntry;
  NS_TEST_EXPECT_MSG_EQ (rcache->AddRoute (entry2), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->LookupRoute (dst2, newEntry), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("2.2.2.2")), false, "trivial");

  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("1.1.1.1")), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (rcache->DeleteRoute (Ipv4Address ("1.1.1.1")), false, "trivial");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrSendBuffTest
 * \brief Unit test for Send Buffer
 */
class BhattackdsrSendBuffTest : public TestCase
{
public:
  BhattackdsrSendBuffTest ();
  ~BhattackdsrSendBuffTest ();
  virtual void
  DoRun (void);
  /// Check size limit function
  void CheckSizeLimit ();
  /// Check timeout function
  void CheckTimeout ();

  bhattackdsr::BhattackdsrSendBuffer q; ///< send buffer
};
BhattackdsrSendBuffTest::BhattackdsrSendBuffTest ()
  : TestCase ("DSR SendBuff"),
    q ()
{
}
BhattackdsrSendBuffTest::~BhattackdsrSendBuffTest ()
{
}
void
BhattackdsrSendBuffTest::DoRun ()
{
  q.SetMaxQueueLen (32);
  NS_TEST_EXPECT_MSG_EQ (q.GetMaxQueueLen (), 32, "trivial");
  q.SetSendBufferTimeout (Seconds (10));
  NS_TEST_EXPECT_MSG_EQ (q.GetSendBufferTimeout (), Seconds (10), "trivial");

  Ptr<const Packet> packet = Create<Packet> ();
  Ipv4Address dst1 = Ipv4Address ("0.0.0.1");
  bhattackdsr::BhattackdsrSendBuffEntry e1 (packet, dst1, Seconds (1));
  q.Enqueue (e1);
  q.Enqueue (e1);
  q.Enqueue (e1);
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.1")), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("1.1.1.1")), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 1, "trivial");
  q.DropPacketWithDst (Ipv4Address ("0.0.0.1"));
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.1")), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 0, "trivial");

  Ipv4Address dst2 = Ipv4Address ("0.0.0.2");
  bhattackdsr::BhattackdsrSendBuffEntry e2 (packet, dst2, Seconds (1));
  q.Enqueue (e1);
  q.Enqueue (e2);
  Ptr<Packet> packet2 = Create<Packet> ();
  bhattackdsr::BhattackdsrSendBuffEntry e3 (packet2, dst2, Seconds (1));
  NS_TEST_EXPECT_MSG_EQ (q.Dequeue (Ipv4Address ("0.0.0.3"), e3), false, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Dequeue (Ipv4Address ("0.0.0.2"), e3), true, "trivial");
  NS_TEST_EXPECT_MSG_EQ (q.Find (Ipv4Address ("0.0.0.2")), false, "trivial");
  q.Enqueue (e2);
  q.Enqueue (e3);
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 2, "trivial");
  Ptr<Packet> packet4 = Create<Packet> ();
  Ipv4Address dst4 = Ipv4Address ("0.0.0.4");
  bhattackdsr::BhattackdsrSendBuffEntry e4 (packet4, dst4, Seconds (20));
  q.Enqueue (e4);
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");
  q.DropPacketWithDst (Ipv4Address ("0.0.0.4"));
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 2, "trivial");

  CheckSizeLimit ();

  Simulator::Schedule (q.GetSendBufferTimeout () + Seconds (1), &BhattackdsrSendBuffTest::CheckTimeout, this);

  Simulator::Run ();
  Simulator::Destroy ();
}
void
BhattackdsrSendBuffTest::CheckSizeLimit ()
{
  Ptr<Packet> packet = Create<Packet> ();
  Ipv4Address dst;
  bhattackdsr::BhattackdsrSendBuffEntry e1 (packet, dst, Seconds (1));

  for (uint32_t i = 0; i < q.GetMaxQueueLen (); ++i)
    {
      q.Enqueue (e1);
    }
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");

  for (uint32_t i = 0; i < q.GetMaxQueueLen (); ++i)
    {
      q.Enqueue (e1);
    }
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 3, "trivial");
}
void
BhattackdsrSendBuffTest::CheckTimeout ()
{
  NS_TEST_EXPECT_MSG_EQ (q.GetSize (), 0, "Must be empty now");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrRreqTableTest
 * \brief Unit test for DSR routing table entry
 */
class BhattackdsrRreqTableTest : public TestCase
{
public:
  BhattackdsrRreqTableTest ();
  ~BhattackdsrRreqTableTest ();
  virtual void
  DoRun (void);
};
BhattackdsrRreqTableTest::BhattackdsrRreqTableTest ()
  : TestCase ("DSR RreqTable")
{
}
BhattackdsrRreqTableTest::~BhattackdsrRreqTableTest ()
{
}
void
BhattackdsrRreqTableTest::DoRun ()
{
  bhattackdsr::RreqTableEntry rt;

  rt.m_reqNo = 2;
  NS_TEST_EXPECT_MSG_EQ (rt.m_reqNo, 2, "trivial");
}
// -----------------------------------------------------------------------------
/**
 * \ingroup bhattackdsr-test
 * \ingroup tests
 *
 * \class BhattackdsrTestSuite
 * \brief DSR test suite
 */
class BhattackdsrTestSuite : public TestSuite
{
public:
  BhattackdsrTestSuite () : TestSuite ("routing-bhattackdsr", UNIT)
  {
    AddTestCase (new BhattackdsrFsHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrRreqHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrRrepHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrSRHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrRerrHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrAckReqHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrAckHeaderTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrCacheEntryTest, TestCase::QUICK);
    AddTestCase (new BhattackdsrSendBuffTest, TestCase::QUICK);
  }
} g_bhattackdsrTestSuite;
