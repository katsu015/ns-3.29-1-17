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

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/header.h"
#include "bhattackdsr-option-header.h"
#include "ns3/ipv4-address.h"
#include "ns3/address-utils.h"
#include "ns3/packet.h"
#include "ns3/enum.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BhattackdsrOptionHeader");

namespace bhattackdsr {

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionHeader);

TypeId BhattackdsrOptionHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionHeader")
    .AddConstructor<BhattackdsrOptionHeader> ()
    .SetParent<Header> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionHeader::BhattackdsrOptionHeader ()
  : m_type (0),
    m_length (0)
{
}

BhattackdsrOptionHeader::~BhattackdsrOptionHeader ()
{
}

void BhattackdsrOptionHeader::SetType (uint8_t type)
{
  m_type = type;
}

uint8_t BhattackdsrOptionHeader::GetType () const
{
  return m_type;
}

void BhattackdsrOptionHeader::SetLength (uint8_t length)
{
  m_length = length;
}

uint8_t BhattackdsrOptionHeader::GetLength () const
{
  return m_length;
}

void BhattackdsrOptionHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)m_type << " length = " << (uint32_t)m_length << " )";
}

uint32_t BhattackdsrOptionHeader::GetSerializedSize () const
{
  return m_length + 2;
}

void BhattackdsrOptionHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (m_type);
  i.WriteU8 (m_length);
  i.Write (m_data.Begin (), m_data.End ());
}

uint32_t BhattackdsrOptionHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  m_type = i.ReadU8 ();
  m_length = i.ReadU8 ();

  m_data = Buffer ();
  m_data.AddAtEnd (m_length);
  Buffer::Iterator dataStart = i;
  i.Next (m_length);
  Buffer::Iterator dataEnd = i;
  m_data.Begin ().Write (dataStart, dataEnd);

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionHeader::GetAlignment () const
{
  Alignment retVal = { 1, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionPad1Header);

TypeId BhattackdsrOptionPad1Header::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionPad1Header")
    .AddConstructor<BhattackdsrOptionPad1Header> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionPad1Header::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionPad1Header::BhattackdsrOptionPad1Header ()
{
  SetType (224);
}

BhattackdsrOptionPad1Header::~BhattackdsrOptionPad1Header ()
{
}

void BhattackdsrOptionPad1Header::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " )";
}

uint32_t BhattackdsrOptionPad1Header::GetSerializedSize () const
{
  return 1;
}

void BhattackdsrOptionPad1Header::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
}

uint32_t BhattackdsrOptionPad1Header::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());

  return GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionPadnHeader);

TypeId BhattackdsrOptionPadnHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionPadnHeader")
    .AddConstructor<BhattackdsrOptionPadnHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionPadnHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionPadnHeader::BhattackdsrOptionPadnHeader (uint32_t pad)
{
  SetType (0);
  NS_ASSERT_MSG (pad >= 2, "PadN must be at least 2 bytes long");
  SetLength (pad - 2);
}

BhattackdsrOptionPadnHeader::~BhattackdsrOptionPadnHeader ()
{
}

void BhattackdsrOptionPadnHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << " )";
}

uint32_t BhattackdsrOptionPadnHeader::GetSerializedSize () const
{
  return GetLength () + 2;
}

void BhattackdsrOptionPadnHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());

  for (int padding = 0; padding < GetLength (); padding++)
    {
      i.WriteU8 (0);
    }
}

uint32_t BhattackdsrOptionPadnHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());

  return GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRreqHeader);

TypeId BhattackdsrOptionRreqHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRreqHeader")
    .AddConstructor<BhattackdsrOptionRreqHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionRreqHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRreqHeader::BhattackdsrOptionRreqHeader ()
  : m_ipv4Address (0)
{
  SetType (1);
  SetLength (6 + m_ipv4Address.size () * 4);
}

BhattackdsrOptionRreqHeader::~BhattackdsrOptionRreqHeader ()
{
}

void BhattackdsrOptionRreqHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

Ipv4Address BhattackdsrOptionRreqHeader::GetTarget ()
{
  return m_target;
}

void BhattackdsrOptionRreqHeader::SetTarget (Ipv4Address target)
{
  m_target = target;
}

void BhattackdsrOptionRreqHeader::AddNodeAddress (Ipv4Address ipv4)
{
  m_ipv4Address.push_back (ipv4);
  SetLength (6 + m_ipv4Address.size () * 4);
}

void BhattackdsrOptionRreqHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (6 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> BhattackdsrOptionRreqHeader::GetNodesAddresses () const
{
  return m_ipv4Address;
}

uint32_t BhattackdsrOptionRreqHeader::GetNodesNumber () const
{
  return m_ipv4Address.size ();
}

void BhattackdsrOptionRreqHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address BhattackdsrOptionRreqHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

void BhattackdsrOptionRreqHeader::SetId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t BhattackdsrOptionRreqHeader::GetId () const
{
  return m_identification;
}

void BhattackdsrOptionRreqHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t BhattackdsrOptionRreqHeader::GetSerializedSize () const
{
  return 8 + m_ipv4Address.size () * 4;
}

void BhattackdsrOptionRreqHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteHtonU16 (m_identification);
  WriteTo (i, m_target);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t BhattackdsrOptionRreqHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadNtohU16 ();
  ReadFrom (i, m_target);

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionRreqHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRrepHeader);

TypeId BhattackdsrOptionRrepHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRrepHeader")
    .AddConstructor<BhattackdsrOptionRrepHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionRrepHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRrepHeader::BhattackdsrOptionRrepHeader ()
  : m_ipv4Address (0)
{
  SetType (2);
  SetLength (2 + m_ipv4Address.size () * 4);
}

BhattackdsrOptionRrepHeader::~BhattackdsrOptionRrepHeader ()
{
}

void BhattackdsrOptionRrepHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

void BhattackdsrOptionRrepHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (2 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> BhattackdsrOptionRrepHeader::GetNodesAddress () const
{
  return m_ipv4Address;
}

void BhattackdsrOptionRrepHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address BhattackdsrOptionRrepHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

Ipv4Address BhattackdsrOptionRrepHeader::GetTargetAddress (std::vector<Ipv4Address> ipv4Address) const
{
  return m_ipv4Address.at (ipv4Address.size () - 1);
}

void BhattackdsrOptionRrepHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t BhattackdsrOptionRrepHeader::GetSerializedSize () const
{
  return 4 + m_ipv4Address.size () * 4;
}

void BhattackdsrOptionRrepHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (0);
  i.WriteU8 (0);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t BhattackdsrOptionRrepHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  i.ReadU8 ();
  i.ReadU8 ();

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionRrepHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionSRHeader);

TypeId BhattackdsrOptionSRHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionSRHeader")
    .AddConstructor<BhattackdsrOptionSRHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionSRHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionSRHeader::BhattackdsrOptionSRHeader ()
  : m_segmentsLeft (0),
    m_ipv4Address (0)
{
  SetType (96);
  SetLength (2 + m_ipv4Address.size () * 4);
}

BhattackdsrOptionSRHeader::~BhattackdsrOptionSRHeader ()
{
}

void BhattackdsrOptionSRHeader::SetSegmentsLeft (uint8_t segmentsLeft)
{
  m_segmentsLeft = segmentsLeft;
}

uint8_t BhattackdsrOptionSRHeader::GetSegmentsLeft () const
{
  return m_segmentsLeft;
}

void BhattackdsrOptionSRHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t BhattackdsrOptionSRHeader::GetSalvage () const
{
  return m_salvage;
}

void BhattackdsrOptionSRHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

void BhattackdsrOptionSRHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (2 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> BhattackdsrOptionSRHeader::GetNodesAddress () const
{
  return m_ipv4Address;
}

void BhattackdsrOptionSRHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address BhattackdsrOptionSRHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

uint8_t BhattackdsrOptionSRHeader::GetNodeListSize () const
{
  return m_ipv4Address.size ();
}

void BhattackdsrOptionSRHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t BhattackdsrOptionSRHeader::GetSerializedSize () const
{
  return 4 + m_ipv4Address.size () * 4;
}

void BhattackdsrOptionSRHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (m_salvage);
  i.WriteU8 (m_segmentsLeft);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t BhattackdsrOptionSRHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  m_segmentsLeft = i.ReadU8 ();

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionSRHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRerrHeader);

TypeId BhattackdsrOptionRerrHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRerrHeader")
    .AddConstructor<BhattackdsrOptionRerrHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionRerrHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRerrHeader::BhattackdsrOptionRerrHeader ()
  : m_errorType (0),
    m_salvage (0),
    m_errorLength (4)
{
  SetType (3);
  SetLength (18);
}

BhattackdsrOptionRerrHeader::~BhattackdsrOptionRerrHeader ()
{
}

void BhattackdsrOptionRerrHeader::SetErrorType (uint8_t errorType)
{
  m_errorType = errorType;
}

uint8_t BhattackdsrOptionRerrHeader::GetErrorType () const
{
  return m_errorType;
}

void BhattackdsrOptionRerrHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t BhattackdsrOptionRerrHeader::GetSalvage () const
{
  return m_salvage;
}

void BhattackdsrOptionRerrHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address BhattackdsrOptionRerrHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void BhattackdsrOptionRerrHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address BhattackdsrOptionRerrHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void BhattackdsrOptionRerrHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress << " )";

}

uint32_t BhattackdsrOptionRerrHeader::GetSerializedSize () const
{
  return 20;
}

void BhattackdsrOptionRerrHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (m_errorType);
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  i.Write (m_errorData.Begin (), m_errorData.End ());
}

uint32_t BhattackdsrOptionRerrHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_errorType = i.ReadU8 ();
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);

  m_errorData = Buffer ();
  m_errorData.AddAtEnd (m_errorLength);
  Buffer::Iterator dataStart = i;
  i.Next (m_errorLength);
  Buffer::Iterator dataEnd = i;
  m_errorData.Begin ().Write (dataStart, dataEnd);

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionRerrHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRerrUnreachHeader);

TypeId BhattackdsrOptionRerrUnreachHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRerrUnreachHeader")
    .AddConstructor<BhattackdsrOptionRerrUnreachHeader> ()
    .SetParent<BhattackdsrOptionRerrHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionRerrUnreachHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRerrUnreachHeader::BhattackdsrOptionRerrUnreachHeader ()
  : m_salvage (0)
{
  SetType (3);
  SetLength (18);
  SetErrorType (1);
}

BhattackdsrOptionRerrUnreachHeader::~BhattackdsrOptionRerrUnreachHeader ()
{
}

void BhattackdsrOptionRerrUnreachHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t BhattackdsrOptionRerrUnreachHeader::GetSalvage () const
{
  return m_salvage;
}

void BhattackdsrOptionRerrUnreachHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address BhattackdsrOptionRerrUnreachHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void BhattackdsrOptionRerrUnreachHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address BhattackdsrOptionRerrUnreachHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void BhattackdsrOptionRerrUnreachHeader::SetUnreachNode (Ipv4Address unreachNode)
{
  m_unreachNode = unreachNode;
}

Ipv4Address BhattackdsrOptionRerrUnreachHeader::GetUnreachNode () const
{
  return m_unreachNode;
}

void BhattackdsrOptionRerrUnreachHeader::SetOriginalDst (Ipv4Address originalDst)
{
  m_originalDst = originalDst;
}

Ipv4Address BhattackdsrOptionRerrUnreachHeader::GetOriginalDst () const
{
  return m_originalDst;
}

void BhattackdsrOptionRerrUnreachHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress
     << " unreach node = " <<  m_unreachNode << " )";
}

uint32_t BhattackdsrOptionRerrUnreachHeader::GetSerializedSize () const
{
  return 20;
}

void BhattackdsrOptionRerrUnreachHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (GetErrorType ());
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  WriteTo (i, m_unreachNode);
  WriteTo (i, m_originalDst);
}

uint32_t BhattackdsrOptionRerrUnreachHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  SetErrorType (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);
  ReadFrom (i, m_unreachNode);
  ReadFrom (i, m_originalDst);

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionRerrUnreachHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRerrUnsupportHeader);

TypeId BhattackdsrOptionRerrUnsupportHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRerrUnsupportHeader")
    .AddConstructor<BhattackdsrOptionRerrUnsupportHeader> ()
    .SetParent<BhattackdsrOptionRerrHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionRerrUnsupportHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRerrUnsupportHeader::BhattackdsrOptionRerrUnsupportHeader ()
  : m_salvage (0)
{
  SetType (3);
  SetLength (14);
  SetErrorType (3);
}

BhattackdsrOptionRerrUnsupportHeader::~BhattackdsrOptionRerrUnsupportHeader ()
{
}

void BhattackdsrOptionRerrUnsupportHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t BhattackdsrOptionRerrUnsupportHeader::GetSalvage () const
{
  return m_salvage;
}

void BhattackdsrOptionRerrUnsupportHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address BhattackdsrOptionRerrUnsupportHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void BhattackdsrOptionRerrUnsupportHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address BhattackdsrOptionRerrUnsupportHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void BhattackdsrOptionRerrUnsupportHeader::SetUnsupported (uint16_t unsupport)
{
  m_unsupport = unsupport;
}

uint16_t BhattackdsrOptionRerrUnsupportHeader::GetUnsupported () const
{
  return m_unsupport;
}

void BhattackdsrOptionRerrUnsupportHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress
     << " unsupported option = " <<  m_unsupport << " )";

}

uint32_t BhattackdsrOptionRerrUnsupportHeader::GetSerializedSize () const
{
  return 16;
}

void BhattackdsrOptionRerrUnsupportHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (GetErrorType ());
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  i.WriteU16 (m_unsupport);

}

uint32_t BhattackdsrOptionRerrUnsupportHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  SetErrorType (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);
  m_unsupport = i.ReadU16 ();

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionRerrUnsupportHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionAckReqHeader);

TypeId BhattackdsrOptionAckReqHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionAckReqHeader")
    .AddConstructor<BhattackdsrOptionAckReqHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionAckReqHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionAckReqHeader::BhattackdsrOptionAckReqHeader ()
  : m_identification (0)

{
  SetType (160);
  SetLength (2);
}

BhattackdsrOptionAckReqHeader::~BhattackdsrOptionAckReqHeader ()
{
}

void BhattackdsrOptionAckReqHeader::SetAckId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t BhattackdsrOptionAckReqHeader::GetAckId () const
{
  return m_identification;
}

void BhattackdsrOptionAckReqHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " id = " << m_identification << " )";
}

uint32_t BhattackdsrOptionAckReqHeader::GetSerializedSize () const
{
  return 4;
}

void BhattackdsrOptionAckReqHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU16 (m_identification);
}

uint32_t BhattackdsrOptionAckReqHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadU16 ();

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionAckReqHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionAckHeader);

TypeId BhattackdsrOptionAckHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionAckHeader")
    .AddConstructor<BhattackdsrOptionAckHeader> ()
    .SetParent<BhattackdsrOptionHeader> ()
    .SetGroupName ("Bhattackdsr")
  ;
  return tid;
}

TypeId BhattackdsrOptionAckHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionAckHeader::BhattackdsrOptionAckHeader ()
  :    m_identification (0)
{
  SetType (32);
  SetLength (10);
}

BhattackdsrOptionAckHeader::~BhattackdsrOptionAckHeader ()
{
}

void BhattackdsrOptionAckHeader::SetAckId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t BhattackdsrOptionAckHeader::GetAckId () const
{
  return m_identification;
}

void BhattackdsrOptionAckHeader::SetRealSrc (Ipv4Address realSrcAddress)
{
  m_realSrcAddress = realSrcAddress;
}

Ipv4Address BhattackdsrOptionAckHeader::GetRealSrc () const
{
  return m_realSrcAddress;
}

void BhattackdsrOptionAckHeader::SetRealDst (Ipv4Address realDstAddress)
{
  m_realDstAddress = realDstAddress;
}

Ipv4Address BhattackdsrOptionAckHeader::GetRealDst () const
{
  return m_realDstAddress;
}

void BhattackdsrOptionAckHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " id = " << m_identification << " real src = " << m_realSrcAddress
     << " real dst = " << m_realDstAddress << " )";

}

uint32_t BhattackdsrOptionAckHeader::GetSerializedSize () const
{
  return 12;
}

void BhattackdsrOptionAckHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU16 (m_identification);
  WriteTo (i, m_realSrcAddress);
  WriteTo (i, m_realDstAddress);
}

uint32_t BhattackdsrOptionAckHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadU16 ();
  ReadFrom (i, m_realSrcAddress);
  ReadFrom (i, m_realDstAddress);

  return GetSerializedSize ();
}

BhattackdsrOptionHeader::Alignment BhattackdsrOptionAckHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}
} /* namespace bhattackdsr */
} /* namespace ns3 */
