//ブラックホール攻撃を実装したオプション

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

#define NS_LOG_APPEND_CONTEXT                                   \
  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }
//+++
#include <list>
#include <ctime>
#include <map>
#include <stdio.h>
#include <stdlib.h> // rand()関数用
#include <time.h>   // time()関数用
#include <fstream>

#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/fatal-error.h"
#include "ns3/node.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-header.h"
#include "ns3/pointer.h"
#include "ns3/node-list.h"
#include "ns3/object-vector.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/icmpv4-l4-protocol.h"
#include "ns3/ip-l4-protocol.h"
#include "bhattackdsr-option-header.h"
#include "bhattackdsr-options.h"
#include "bhattackdsr-rcache.h"

//#define fname ”romn.txt”;

u_int32_t sendACKcount = 0;
u_int16_t fakehops = 3;
u_int32_t malicious = 7;
u_int32_t malicious2 = 8;
u_int32_t malicious3 = 9;
u_int32_t erraddress = 3;
u_int32_t dropcount = 0;
//u_int32_t sendtomcount = 0;
double perc = 0.25;

#define fname "route.txt"

using namespace std;
std::ofstream outputfile(fname);


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BhattackdsrOptions");

namespace bhattackdsr {

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptions);

TypeId BhattackdsrOptions::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptions")
    .SetParent<Object> ()
    .SetGroupName ("Bhattackdsr")
    .AddAttribute ("OptionNumber", "The Bhattackdsr option number.",
                   UintegerValue (0),
                   MakeUintegerAccessor (&BhattackdsrOptions::GetOptionNumber),
                   MakeUintegerChecker<uint8_t> ())
    .AddTraceSource ("Drop",
                     "Packet dropped.",
                     MakeTraceSourceAccessor (&BhattackdsrOptions::m_dropTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("Rx",
                     "Receive DSR packet.",
                     MakeTraceSourceAccessor (&BhattackdsrOptions::m_rxPacketTrace),
                     "ns3::bhattackdsr::BhattackdsrOptionSRHeader::TracedCallback")
  ;
  return tid;
}

BhattackdsrOptions::BhattackdsrOptions ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptions::~BhattackdsrOptions ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void BhattackdsrOptions::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}

Ptr<Node> BhattackdsrOptions::GetNode () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_node;
}

bool BhattackdsrOptions::ContainAddressAfter (Ipv4Address ipv4Address, Ipv4Address destAddress, std::vector<Ipv4Address> &nodeList)
{
  NS_LOG_FUNCTION (this << ipv4Address << destAddress);
  std::vector<Ipv4Address>::iterator it = find (nodeList.begin (), nodeList.end (), destAddress);

  for (std::vector<Ipv4Address>::iterator i = it; i != nodeList.end (); ++i)
    {
      if ((ipv4Address == (*i)) && ((*i) != nodeList.back ()))
        {
          return true;
        }
    }
  return false;
}

std::vector<Ipv4Address>
BhattackdsrOptions::CutRoute (Ipv4Address ipv4Address, std::vector<Ipv4Address> &nodeList)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  std::vector<Ipv4Address>::iterator it = find (nodeList.begin (), nodeList.end (), ipv4Address);
  std::vector<Ipv4Address> cutRoute;
  for (std::vector<Ipv4Address>::iterator i = it; i != nodeList.end (); ++i)
    {
      cutRoute.push_back (*i);
    }
  return cutRoute;
}

Ptr<Ipv4Route> BhattackdsrOptions::SetRoute (Ipv4Address nextHop, Ipv4Address srcAddress)
{
  NS_LOG_FUNCTION (this << nextHop << srcAddress);
  m_ipv4Route = Create<Ipv4Route> ();
  m_ipv4Route->SetDestination (nextHop);
  m_ipv4Route->SetGateway (nextHop);
  m_ipv4Route->SetSource (srcAddress);
  return m_ipv4Route;
}

bool BhattackdsrOptions::ReverseRoutes (std::vector<Ipv4Address> & vec)
{
  NS_LOG_FUNCTION (this);
  std::vector<Ipv4Address> vec2 (vec);
  vec.clear ();    // To ensure vec is empty before start
  for (std::vector<Ipv4Address>::reverse_iterator ri = vec2.rbegin (); ri
       != vec2.rend (); ++ri)
    {
      vec.push_back (*ri);
    }

  if ((vec.size () == vec2.size ()) && (vec.front () == vec2.back ()))
    {
      return true;
    }
  return false;
}

Ipv4Address BhattackdsrOptions::SearchNextHop (Ipv4Address ipv4Address, std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  Ipv4Address nextHop;
  NS_LOG_DEBUG ("the vector size " << vec.size ());
  if (vec.size () == 2)
    {
      NS_LOG_DEBUG ("The two nodes are neighbors");
      nextHop = vec[1];
      return nextHop;
    }
  else
    {
      if (ipv4Address == vec.back ())
        {
          NS_LOG_DEBUG ("We have reached to the final destination " << ipv4Address << " " << vec.back ());
          return ipv4Address;
        }
      for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
        {
          if (ipv4Address == (*i))
            {
              nextHop = *(++i);
              return nextHop;
            }
        }
    }
  NS_LOG_DEBUG ("next hop address not found, route corrupted");
  Ipv4Address none = "0.0.0.0";
  return none;
}

Ipv4Address BhattackdsrOptions::ReverseSearchNextHop (Ipv4Address ipv4Address, std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  Ipv4Address nextHop;
  if (vec.size () == 2)
    {
      NS_LOG_DEBUG ("The two nodes are neighbors");
      nextHop = vec[0];
      return nextHop;
    }
  else
    {
      for (std::vector<Ipv4Address>::reverse_iterator ri = vec.rbegin (); ri != vec.rend (); ++ri)
        {
          if (ipv4Address == (*ri))
            {
              nextHop = *(++ri);
              return nextHop;
            }
        }
    }
  NS_LOG_DEBUG ("next hop address not found, route corrupted");
  Ipv4Address none = "0.0.0.0";
  return none;
}

Ipv4Address BhattackdsrOptions::ReverseSearchNextTwoHop  (Ipv4Address ipv4Address, std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  Ipv4Address nextTwoHop;
  NS_LOG_DEBUG ("The vector size " << vec.size ());
  NS_ASSERT (vec.size () > 2);
  for (std::vector<Ipv4Address>::reverse_iterator ri = vec.rbegin (); ri != vec.rend (); ++ri)
    {
      if (ipv4Address == (*ri))
        {
          nextTwoHop = *(ri + 2);
          return nextTwoHop;
        }
    }
  NS_FATAL_ERROR ("next hop address not found, route corrupted");
  outputfile << "next hop address not found, route corrupted" << '\n';
  Ipv4Address none = "0.0.0.0";
  return none;
}

void BhattackdsrOptions::PrintVector (std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this);
  /*
   * Check elements in a route vector
   */
  if (!vec.size ())
    {
      NS_LOG_DEBUG ("The vector is empty");
    }
  else
    {
      NS_LOG_DEBUG ("Print all the elements in a vector");
      for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
        {
          NS_LOG_DEBUG ("The ip address " << *i);
        }
    }
}

bool BhattackdsrOptions::IfDuplicates (std::vector<Ipv4Address>& vec, std::vector<Ipv4Address>& vec2)
{
  NS_LOG_FUNCTION (this);
  for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
    {
      for (std::vector<Ipv4Address>::const_iterator j = vec2.begin (); j != vec2.end (); ++j)
        {
          if ((*i) == (*j))
            {
              return true;
            }
          else
            {
              continue;
            }
        }
    }
  return false;
}

bool BhattackdsrOptions::CheckDuplicates (Ipv4Address ipv4Address, std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
    {
      if ((*i) == ipv4Address)
        {
          return true;
        }
      else
        {
          continue;
        }
    }
  return false;
}

void BhattackdsrOptions::RemoveDuplicates (std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this);
  //Remove duplicate ip address from the route if any, should not happen with normal behavior nodes
  std::vector<Ipv4Address> vec2 (vec); // declare vec2 as a copy of the vec
  PrintVector (vec2); // Print all the ip address in the route
  vec.clear (); // clear vec
  for (std::vector<Ipv4Address>::const_iterator i = vec2.begin (); i != vec2.end (); ++i)
    {
      if (vec.empty ())
        {
          vec.push_back (*i);
          continue;
        }
      else
        {
          for (std::vector<Ipv4Address>::iterator j = vec.begin (); j != vec.end (); ++j)
            {
              if ((*i) == (*j))
                {
                  if ((j + 1) != vec.end ())
                    {
                      vec.erase (j + 1, vec.end ());   // Automatic shorten the route
                      break;
                    }
                  else
                    {
                      break;
                    }
                }
              else if (j == (vec.end () - 1))
                {
                  vec.push_back (*i);
                  break;
                }
              else
                {
                  continue;
                }
            }
        }
    }
}

uint32_t
BhattackdsrOptions::GetIDfromIP (Ipv4Address address)
{
  NS_LOG_FUNCTION (this << address);
  int32_t nNodes = NodeList::GetNNodes ();
  for (int32_t i = 0; i < nNodes; ++i)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      if (ipv4->GetAddress (1, 0).GetLocal () == address)
        {
          return i;
        }
    }
  return 255;
}

Ptr<Node> BhattackdsrOptions::GetNodeWithAddress (Ipv4Address ipv4Address)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  int32_t nNodes = NodeList::GetNNodes ();
  for (int32_t i = 0; i < nNodes; ++i)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      int32_t ifIndex = ipv4->GetInterfaceForAddress (ipv4Address);
      if (ifIndex != -1)
        {
          return node;
        }
    }
  return 0;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionPad1);

TypeId BhattackdsrOptionPad1::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionPad1")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionPad1> ()
  ;
  return tid;
}

BhattackdsrOptionPad1::BhattackdsrOptionPad1 ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionPad1::~BhattackdsrOptionPad1 ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

uint8_t BhattackdsrOptionPad1::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();

  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionPad1::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);
  Ptr<Packet> p = packet->Copy ();
  BhattackdsrOptionPad1Header pad1Header;
  p->RemoveHeader (pad1Header);

  isPromisc = false;

  return pad1Header.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionPadn);

TypeId BhattackdsrOptionPadn::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionPadn")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionPadn> ()
  ;
  return tid;
}

BhattackdsrOptionPadn::BhattackdsrOptionPadn ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionPadn::~BhattackdsrOptionPadn ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

uint8_t BhattackdsrOptionPadn::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionPadn::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);

  Ptr<Packet> p = packet->Copy ();
  BhattackdsrOptionPadnHeader padnHeader;
  p->RemoveHeader (padnHeader);

  isPromisc = false;

  return padnHeader.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRreq);

TypeId BhattackdsrOptionRreq::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRreq")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionRreq> ()
  ;
  return tid;
}

TypeId BhattackdsrOptionRreq::GetInstanceTypeId () const
{
  return GetTypeId ();
}

BhattackdsrOptionRreq::BhattackdsrOptionRreq ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionRreq::~BhattackdsrOptionRreq ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

uint8_t BhattackdsrOptionRreq::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();

  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionRreq::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{

  //悪意のあるノードの設定
  u_int32_t malicious = 7;
  //RREQが送信されてるかチェック
  //printf("RREQ PROCESS .1 \n" );
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header <<
     (uint32_t)protocol << isPromisc);
  // Fields from IP header
  Ipv4Address srcAddress = ipv4Header.GetSource ();
  //ソースコードの表示
  //std::cout << "/*srcAddress = */" << srcAddress << '\n';
  /*
   * \ IP送信元アドレスが私たち自身のアドレスと等しい場合、これは発信された要求パケットです
    * \ノード自体で、破棄する
   */
  if (source == ipv4Address)
    {
      NS_LOG_DEBUG ("Discard the packet since it was originated from same source address");
      m_dropTrace (packet); // call the drop trace to show in the tracing
        //printf("RREQ PROCESS .2\n" );
      return 0;
    }
  /*
   * ipv4アドレスに関連付けられたノードを取得し、ノードからいくつかのオブジェクトを取得して、さらに使用するために出発します
   */


  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();

  Ptr<Packet> p = packet->Copy (); // 注：ここのパケットには、固定サイズのbhattackdsrヘッダーが含まれていません
  /*
   * \ヘッダーを削除する前にルーターのアドレスフィールドの数を取得する
    * \パケットを覗いて値を取得
   */
  uint8_t buf[2];
  p->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 6) / 4;
//    outputfile <<" numberaddress "<< (uint32_t)numberAddress <<  "\n" ;

  NS_LOG_DEBUG ("The number of Ip addresses " << (uint32_t)numberAddress);
  if (numberAddress >= 255)
    {
      NS_LOG_DEBUG ("Discard the packet, malformed header since two many ip addresses in route");
      m_dropTrace (packet); // call the drop trace to show in the tracing
        printf("RREQ PROCESS .3\n" );
      return 0;
    }

  /*
   * Create the bhattackdsr rreq header
   */
  BhattackdsrOptionRreqHeader rreq;
  /*
   * ピークデータの値でアドレスの数を設定し、rreqヘッダーを削除します
   */
  rreq.SetNumberAddress (numberAddress);
  // Remove the route request header
  p->RemoveHeader (rreq);
  // Verify the option length
  uint8_t length = rreq.GetLength ();
  if (length % 2 != 0)
    {
      NS_LOG_LOGIC ("Malformed header. Drop!");
      m_dropTrace (packet); // call drop trace
        printf("RREQ PROCESS .4\n" );
      return 0;
    }
  // リクエストIDを確認するためにrreq IDを確認してください
  uint16_t requestId = rreq.GetId ();
  //std::cout << requestId << '\n';
  // ターゲットアドレスは、データパケットを送信する場所です。
  Ipv4Address targetAddress = rreq.GetTarget ();
  //std::cout <<"targetAddress " << targetAddress <<"\n";
  // ルートリクエストヘッダーからノードリストと送信元アドレスを取得する
  std::vector<Ipv4Address> mainVector = rreq.GetNodesAddresses ();
  std::vector<Ipv4Address> nodeList (mainVector);

  // このリクエストの実際の送信元アドレスを取得します。保存を受信したかどうかを確認するときに使用されます
  // 前にルートリクエスト
  Ipv4Address sourceAddress = nodeList.front ();
  PrintVector (nodeList);
  /*
   * 後で使用するためにbhattackdsrルーティングヘッダーを作成します
   */
  BhattackdsrRoutingHeader bhattackdsrRoutingHeader;
  bhattackdsrRoutingHeader.SetNextHeader (protocol);
  bhattackdsrRoutingHeader.SetMessageType (1);
  bhattackdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
  bhattackdsrRoutingHeader.SetDestId (255);

  // このリクエストを受信したかどうかを確認します。受信していない場合は、後で使用するためにテーブルにリクエストを保存し、見つからない場合はfalseを返し、新しく受信したソースリクエストエントリをキャッシュにプッシュします

  // TTL値を取得します。これは、パケットが転送されるかどうかをテストするために使用されます
  uint8_t ttl = ipv4Header.GetTtl ();
  bool dupRequest = false;  // 重複したリクエストのチェック値を初期化します
  if (ttl)
    {
      // ttl値が0でない場合、このリクエストは転送され、ソースエントリに保存する必要があります
      dupRequest = bhattackdsr->FindSourceEntry (sourceAddress, targetAddress, requestId);
    }
  /*
   * ルートリクエストを処理する前に、2つのことを確認する必要があります
    * 1.これが受信したリクエストとまったく同じ場合は、無視します
    * 2.アドレスが既にパスリストにある場合は無視します
    * 3.それ以外の場合はさらに処理する
   */

  if (dupRequest)
    {
      // 以前にこの同じルートリクエストを受信しましたが、今は転送していません
      NS_LOG_LOGIC ("Duplicate request. Drop!");
      m_dropTrace (packet); // call drop trace
      return 0;
    }

  else if (CheckDuplicates (ipv4Address, nodeList))
    {
      /*
       * ルートにすでにノードアドレスが含まれている場合は、要求パケットをドロップします
       */
      m_dropTrace (packet);    // call drop trace
      NS_LOG_DEBUG ("Our node address is already seen in the route, drop the request");
      return 0;
    }
  else
    {
      //ブラックホール攻撃

      if (GetIDfromIP (ipv4Address) == malicious)
      {
        NS_LOG_DEBUG ("---Starting BHAttack ---");
      }
      // ノードは、ブラックリスト内のノードから受信したすべてのRREQを無視します
      BhattackdsrRouteCacheEntry toPrev;
      bool isRouteInCache = bhattackdsr->LookupRoute (targetAddress,
                                              toPrev);
      BhattackdsrRouteCacheEntry::IP_VECTOR ip = toPrev.GetVector (); // 独自のルートキャッシュからdstへのルート
      PrintVector (ip);
      std::vector<Ipv4Address> saveRoute (nodeList);
      PrintVector (saveRoute);
      bool areThereDuplicates = IfDuplicates (ip,
                                              saveRoute);
      /*
       *  逆ルートが作成または更新されると、ルートに対する次のアクションも実行されます。
        * 3.ルーティングテーブル内のネクストホップは、RREQを受信したノードになります
        * 4.ホップカウントは、RREQメッセージのホップカウントからコピーされます。
        * /

       //ノードは、次のいずれかの場合にRREPを生成します。
       //（i）それ自体が宛先であり、
       / *
        *自分のIPアドレスに等しいターゲットアドレス
       */
      NS_LOG_DEBUG ("The target address over here " << targetAddress << " and the ip address " << ipv4Address << " and the source address " << mainVector[0]);
      //std::cout <<"mainvectorr" <<mainVector[0] << '\n';
      //偽造RREPの生成と送信


      //通常のルーティングにおけるRREP
      if (targetAddress == ipv4Address)
        {
          /*
          std::cout << "正規のルーティングによるRREP" << '\n';
          std::cout << "ソースノードは　" << mainVector[0] << '\n';
          std::cout << "現在のノードは　" << ipv4Address << '\n';
          std::cout << "宛先ノードは　" << targetAddress << '\n';
          */
          if (GetIDfromIP (ipv4Address) == malicious)
          {
          outputfile << "mali" << '\n';
        }

          Ipv4Address nextHop; // 使用するネクストホップアドレスを宣言する
          if (nodeList.size () == 1)
            {
              NS_LOG_DEBUG ("These two nodes are neighbors");
              //std::cout << "Error\n";
              m_finalRoute.clear ();
              /// TODOはsrcAddressをソースに変更しました。どちらにしてもかまいません。後で確認してください
              m_finalRoute.push_back (source);     // リクエストの発信者のアドレスをプッシュバックする
              m_finalRoute.push_back (ipv4Address);    // 自分の住所を押し戻す
              nextHop = srcAddress;
            }
          else
            {
              std::vector<Ipv4Address> changeRoute (nodeList);
              changeRoute.push_back (ipv4Address);    // 自分の住所を押し戻す

          /*
              for(int i =0; i < (int)changeRoute.size();i++){
                std::cout << changeRoute[i] <<"\n";
              }
        */

              m_finalRoute.clear ();              // 明確なルートベクトルを取得する
            //  std::cout << "/* 正規ルート */
            ////" << '\n';

              for (std::vector<Ipv4Address>::iterator i = changeRoute.begin (); i != changeRoute.end (); ++i)
                {
                  //正規ルートの表示
                //  std::cout << *i << '\n';
                  m_finalRoute.push_back (*i);  // 出発地から目的地までの完全なルートを取得する
                }
              outputfile << "/--------/" << '\n';
              outputfile << "/finalroute/" << '\n';
              for (std::vector<Ipv4Address>::iterator i = m_finalRoute.begin (); i != m_finalRoute.end (); ++i)
                {
                  //ファイナルルートの表示
                  outputfile << *i << '\n';
                }
              PrintVector (m_finalRoute);
             outputfile << "/--------/" << '\n';

              nextHop = ReverseSearchNextHop (ipv4Address, m_finalRoute); // get the next hop
            //  std::cout << "/* nextHop */
            ////" << nextHop << '\n';
            }

          BhattackdsrOptionRrepHeader rrep;
          rrep.SetNodesAddress (m_finalRoute);     // ルート応答ヘッダーにノードアドレスを設定します
          NS_LOG_DEBUG ("The nextHop address " << nextHop);
          Ipv4Address replyDst = m_finalRoute.front ();
          /*
           *この部分は、パケットにbhattackdsrヘッダーを追加し、ルート応答パケットを送信します
           */

          BhattackdsrRoutingHeader bhattackdsrRoutingHeader;
          bhattackdsrRoutingHeader.SetNextHeader (protocol);
          bhattackdsrRoutingHeader.SetMessageType (1);
          bhattackdsrRoutingHeader.SetSourceId (GetIDfromIP (ipv4Address));
          bhattackdsrRoutingHeader.SetDestId (GetIDfromIP (replyDst));
          // Set the route for route reply
          SetRoute (nextHop, ipv4Address);

          uint8_t length = rrep.GetLength ();  // タイプヘッダーを除くrrepヘッダーの長さを取得します
          bhattackdsrRoutingHeader.SetPayloadLength (length + 2);
          bhattackdsrRoutingHeader.AddBhattackdsrOption (rrep);
          Ptr<Packet> newPacket = Create<Packet> ();
          newPacket->AddHeader (bhattackdsrRoutingHeader);
          bhattackdsr->ScheduleInitialReply (newPacket, ipv4Address, nextHop, m_ipv4Route);
          /*
           * rreq発信元へのルートエントリを作成し、ルートキャッシュに保存します。ルートを逆にする必要もあります
           */
          // std::cout << "finalroute" << '\n';

          PrintVector (m_finalRoute);
          if (ReverseRoutes (m_finalRoute))
            {

              PrintVector (m_finalRoute);
              Ipv4Address dst = m_finalRoute.back ();
              bool addRoute = false;
              if (numberAddress > 0)
                {
                  BhattackdsrRouteCacheEntry toSource (/*IP_VECTOR=*/
                  m_finalRoute, /*dst=*/
                                                         dst, /*expire time=*/ ActiveRouteTimeout);

                  if (bhattackdsr->IsLinkCache ())
                    {
                      addRoute = bhattackdsr->AddRoute_Link (m_finalRoute, ipv4Address);
                    }
                  else
                    {
                      addRoute = bhattackdsr->AddRoute (toSource);
                    }
                }
              else
                {
                  NS_LOG_DEBUG ("Abnormal RouteRequest");
                  return 0;
                }

              if (addRoute)
                {
                  /*
                   * dstへのルートを見つけ、ソースルートオプションヘッダーを構築します
                   */

                  BhattackdsrOptionSRHeader sourceRoute;
                  NS_LOG_DEBUG ("The route length " << m_finalRoute.size ());
                  sourceRoute.SetNodesAddress (m_finalRoute);

                  /// TODO !!!!!!!!!!!!!!
                     ///この部分について考えてみましょう。ルートを追加しました。
                     ///安定性を今すぐ上げる必要はないか?????
                  // if (bhattackdsr->IsLinkCache ())
                  //   {
                  //     bhattackdsr->UseExtends (m_finalRoute);
                  //   }
                  sourceRoute.SetSegmentsLeft ((m_finalRoute.size () - 2));
                  // The salvage value here is 0
                  sourceRoute.SetSalvage (0);
                  Ipv4Address nextHop = SearchNextHop (ipv4Address, m_finalRoute); // Get the next hop address
                  NS_LOG_DEBUG ("The nextHop address " << nextHop);

                  if (nextHop == "0.0.0.0")
                    {
                      bhattackdsr->PacketNewRoute (bhattackdsrP, ipv4Address, dst, protocol);
                      return 0;
                    }
                  SetRoute (nextHop, ipv4Address);
                  /*
                   * 送信バッファからデータパケットを送信します
                   */
                 bhattackdsr->SendPacketFromBuffer (sourceRoute, nextHop, protocol);
                  // //データパケットを送信した後、宛先のルート要求タイマーをキャンセルします

                  bhattackdsr->CancelRreqTimer (dst, true);
                }
              else
                {
                  NS_LOG_DEBUG ("The route is failed to add in cache");
                  return 0;
                }
            }
          else
            {
              NS_LOG_DEBUG ("Unable to reverse route");
              return 0;
            }
          isPromisc = false;
          return rreq.GetSerializedSize ();
        }

      /*
       * （ii）または、宛先へのアクティブなルートがあり、リクエストヘッダーとルートキャッシュに基づいて応答を送信します。
        * d = H *（h-1 + r）からのランダムな値に基づいて遅延する必要があります。これにより、可能なルートを回避できます。
        *返信の嵐。 また、2つのベクターに重複が含まれていないことを確認します（へのルートの一部
        *ルートキャッシュからの宛先およびこれまでに収集されたルート）。 その場合、見つかったルートを使用しないでください
        *ルートリクエストを転送します。
       */
      else if (isRouteInCache && !areThereDuplicates)
        {
          if (GetIDfromIP (ipv4Address) == malicious)
          {
          outputfile << "mali(2)" << '\n';
        }
        //  std::cout << "/* ヘッダーとルートキャッシュの処理 */" << '\n';
          m_finalRoute.clear ();                // Clear the final route vector
          /**
           * 中間ノードのアドレスをソースからこのノードにプッシュバックします
           */
      //     std::cout << "/* 中間ノードのアドレス */" << '\n';
          for (std::vector<Ipv4Address>::iterator i = saveRoute.begin (); i != saveRoute.end (); ++i)
            {
        //      std::cout << *i << '\n';
              m_finalRoute.push_back (*i);
            }
          /**
           * このノードのアドレスを含め、ルートキャッシュで見つかったルートベクトルを宛先にプッシュバックします。
           */
        //   std::cout << "/* ルートキャッシュで見つかったルートベクトル */" << '\n';
          for (std::vector<Ipv4Address>::iterator j = ip.begin (); j != ip.end (); ++j)
            {
            //  std::cout << *j << '\n';
              m_finalRoute.push_back (*j);
            }
          /*
           * rreq発信元へのルートエントリを作成し、ルートキャッシュに保存します。ルートを逆にする必要もあります
           */
          bool addRoute = false;
          std::vector<Ipv4Address> reverseRoute (m_finalRoute);

          if (ReverseRoutes (reverseRoute))
            {
              saveRoute.push_back (ipv4Address);
              ReverseRoutes (saveRoute);
              Ipv4Address dst = saveRoute.back ();
              NS_LOG_DEBUG ("This is the route save in route cache");
              PrintVector (saveRoute);

              BhattackdsrRouteCacheEntry toSource (/*IP_VECTOR=*/ saveRoute, /*dst=*/ dst, /*expire time=*/ ActiveRouteTimeout);
              NS_ASSERT (saveRoute.front () == ipv4Address);
              // ルートキャッシュにルートエントリを追加する
              if (bhattackdsr->IsLinkCache ())
                {
                  addRoute = bhattackdsr->AddRoute_Link (saveRoute, ipv4Address);
                }
              else
                {
                  addRoute = bhattackdsr->AddRoute (toSource);
                }

              if (addRoute)
                {
                  NS_LOG_LOGIC ("We have added the route and search send buffer for packet with destination " << dst);
                  /*
                   * dstルートを見つけ、ソースルートオプションヘッダーを構築します
                   */
                  BhattackdsrOptionSRHeader sourceRoute;
                  PrintVector (saveRoute);

                  sourceRoute.SetNodesAddress (saveRoute);
                  // if (bhattackdsr->IsLinkCache ())
                  //   {
                  //     bhattackdsr->UseExtends (saveRoute);
                  //   }
                  sourceRoute.SetSegmentsLeft ((saveRoute.size () - 2));
                  uint8_t salvage = 0;
                  sourceRoute.SetSalvage (salvage);
                  Ipv4Address nextHop = SearchNextHop (ipv4Address, saveRoute);     // Get the next hop address
                  NS_LOG_DEBUG ("The nextHop address " << nextHop);

                  if (nextHop == "0.0.0.0")
                    {
                      bhattackdsr->PacketNewRoute (bhattackdsrP, ipv4Address, dst, protocol);
                      return 0;
                    }
                  SetRoute (nextHop, ipv4Address);
                  /*
                   * パケット再試行をスケジュールする
                   */
                  bhattackdsr->SendPacketFromBuffer (sourceRoute, nextHop, protocol);
                  // 宛先のルート要求タイマーをキャンセルします
                  bhattackdsr->CancelRreqTimer (dst, true);
                }
              else
                {
                  NS_LOG_DEBUG ("The route is failed to add in cache");
                  return 0;
                }
            }
          else
            {
              NS_LOG_DEBUG ("Unable to reverse the route");
              return 0;
            }

          /*
           * 重複を削除する前に、最初に次のホップアドレスを特定する必要があります
           */
          Ipv4Address nextHop = ReverseSearchNextHop (ipv4Address, m_finalRoute);
          /*
           * 最初に重複したIPアドレスを削除して自動的にルートを短縮し、次に逆に
            *次ホップアドレスを検索
           */
          // Set the route



          uint16_t hops = m_finalRoute.size ();

          SetRoute (nextHop, ipv4Address);
          if (GetIDfromIP (ipv4Address) == malicious)
          {
            hops = fakehops;
          }

          BhattackdsrOptionRrepHeader rrep;
          rrep.SetNodesAddress (m_finalRoute);         // ルート応答ヘッダーにノードアドレスを設定します
           //返信の実際のソースを取得します
          Ipv4Address realSource = m_finalRoute.back ();
          PrintVector (m_finalRoute);
          NS_LOG_DEBUG ("This is the full route from " << realSource << " to " << m_finalRoute.front ());
          /*
           * この部分は、パケットにbhattackdsrヘッダーを追加し、ルート応答パケットを送信します
           */
          BhattackdsrRoutingHeader bhattackdsrRoutingHeader;
          bhattackdsrRoutingHeader.SetNextHeader (protocol);
          bhattackdsrRoutingHeader.SetMessageType (1);
          bhattackdsrRoutingHeader.SetSourceId (GetIDfromIP (realSource));
          bhattackdsrRoutingHeader.SetDestId (255);

          uint8_t length = rrep.GetLength ();      // タイプヘッダーを除くrrepヘッダーの長さを取得します
          bhattackdsrRoutingHeader.SetPayloadLength (length + 2);
          bhattackdsrRoutingHeader.AddBhattackdsrOption (rrep);
          Ptr<Packet> newPacket = Create<Packet> ();
          newPacket->AddHeader (bhattackdsrRoutingHeader);
          bhattackdsr->ScheduleCachedReply (newPacket, ipv4Address, nextHop, m_ipv4Route, hops);
          isPromisc = false;
          return rreq.GetSerializedSize ();
        }
      /*
       * （iii）どのタイプのルートも見つかりませんでした
       */
      else
        {


            if (GetIDfromIP (ipv4Address) == malicious)
            {
            outputfile << "malicheckaerror" << '\n';
          }

          mainVector.push_back (ipv4Address);
          NS_ASSERT (mainVector.front () == source);
          NS_LOG_DEBUG ("Print out the main vector");
          //u_int8_t mainID = GetIDfromIP (ipv4Address);
        //  printf("mainId %d\n", mainID );
          PrintVector (mainVector);
          rreq.SetNodesAddress (mainVector);

          Ptr<Packet> errP = p->Copy ();
          if (errP->GetSize ())
            {
              NS_LOG_DEBUG ("Error header included");
              BhattackdsrOptionRerrUnreachHeader rerr;
              p->RemoveHeader (rerr);
              Ipv4Address errorSrc = rerr.GetErrorSrc ();
              Ipv4Address unreachNode = rerr.GetUnreachNode ();
              Ipv4Address errorDst = rerr.GetErrorDst ();

              if ((errorSrc == srcAddress) && (unreachNode == ipv4Address))
                {
                  NS_LOG_DEBUG ("The error link back to work again");
                  uint16_t length = rreq.GetLength ();
                  NS_LOG_DEBUG ("The RREQ header length " <<  length);
                  bhattackdsrRoutingHeader.AddBhattackdsrOption (rreq);
                  bhattackdsrRoutingHeader.SetPayloadLength (length + 2);
                }
              else
                {
                  bhattackdsr->DeleteAllRoutesIncludeLink (errorSrc, unreachNode, ipv4Address);

                  BhattackdsrOptionRerrUnreachHeader newUnreach;
                  newUnreach.SetErrorType (1);
                  newUnreach.SetErrorSrc (errorSrc);
                  newUnreach.SetUnreachNode (unreachNode);
                  newUnreach.SetErrorDst (errorDst);
                  newUnreach.SetSalvage (rerr.GetSalvage ()); // パケットを回収するかどうかについての値を設定します
                  uint16_t length = rreq.GetLength () + newUnreach.GetLength ();
                  NS_LOG_DEBUG ("The RREQ and newUnreach header length " <<  length);
                  bhattackdsrRoutingHeader.SetPayloadLength (length + 4);
                  bhattackdsrRoutingHeader.AddBhattackdsrOption (rreq);
                  bhattackdsrRoutingHeader.AddBhattackdsrOption (newUnreach);
                }
            }
          else
            {
              uint16_t length = rreq.GetLength ();
              NS_LOG_DEBUG ("The RREQ header length " <<  length);
              bhattackdsrRoutingHeader.AddBhattackdsrOption (rreq);
              bhattackdsrRoutingHeader.SetPayloadLength (length + 2);
            }
          // TTL値を取得する
          uint8_t ttl = ipv4Header.GetTtl ();
          /*
          * パケットタグのTTL値を1つ減らすと、このタグはIPレイヤー3送信機能に移動します
           *およびTTL値が0に等しい場合にパケットをドロップ
          */
          NS_LOG_DEBUG ("The ttl value here " << (uint32_t)ttl);
          if (ttl)
            {
              Ptr<Packet> interP = Create<Packet> ();
              SocketIpTtlTag tag;
              tag.SetTtl (ttl - 1);
              interP->AddPacketTag (tag);
              interP->AddHeader (bhattackdsrRoutingHeader);
              bhattackdsr->ScheduleInterRequest (interP);
              isPromisc = false;
            }
          return rreq.GetSerializedSize ();
        }

    }
  //unreachable:  return rreq.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRrep);

TypeId BhattackdsrOptionRrep::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRrep")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionRrep> ()
  ;
  return tid;
}

BhattackdsrOptionRrep::BhattackdsrOptionRrep ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionRrep::~BhattackdsrOptionRrep ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId BhattackdsrOptionRrep::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint8_t BhattackdsrOptionRrep::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();

  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionRrep::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  //std::cout << "/* RREPの処理 */" << '\n';
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);

  Ptr<Packet> p = packet->Copy ();

  // ルーターのアドレスフィールドの数を取得する
  uint8_t buf[2];
  p->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 2) / 4;

  BhattackdsrOptionRrepHeader rrep;
  rrep.SetNumberAddress (numberAddress);  // ヘッダーのIPアドレスの数を設定して、ヘッダーを逆シリアル化するためのスペースを確保します
  p->RemoveHeader (rrep);

  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();

  NS_LOG_DEBUG ("The next header value " << (uint32_t)protocol);

  std::vector<Ipv4Address> nodeList = rrep.GetNodesAddress ();
  /**
   * nodeListの最後の要素である宛先アドレスを取得します
   */
   //std::cout << "/*RREPから取り出した nodeList */" << '\n';
   for (std::vector<Ipv4Address>::iterator i = nodeList.begin (); i != nodeList.end (); ++i)
     {
    //   std::cout << *i << '\n';
     }

  Ipv4Address targetAddress = nodeList.front ();
//  std::cout << "/* RREPを送信するtargetAddress = */" << nodeList.front () << '\n';
  // RREPオプションが宛先に到達した場合
  if (targetAddress == ipv4Address)
    {
      RemoveDuplicates (nodeList); // これは削除しなかったため、中間ノードからのルート応答用です
                                    //そこに複製します
      if (nodeList.size () == 0)
        {
          NS_LOG_DEBUG ("The route we have contains 0 entries");
          return 0;
        }
      /**
       * nodeListの最後の要素であるデータパケットの宛先アドレスを取得します
       */
      Ipv4Address dst = nodeList.back ();
    //  std::cout << "/* RREPが宛先に到達したとき */" << '\n';
    //  std::cout << " nodeListの最後の要素であるデータパケットの宛先アドレスdst =" << dst << '\n';
      /**
       * 新しく見つかったルートをルートキャッシュに追加します
        *ルートは次のようになります。
        * \\ "srcAddress" + "中間ノードアドレス" + "targetAddress"
       */
      BhattackdsrRouteCacheEntry toDestination (/*IP_VECTOR=*/ nodeList, /*dst=*/ dst, /*expire time=*/ ActiveRouteTimeout);

      NS_ASSERT (nodeList.front () == ipv4Address);
      bool addRoute = false;
      if (bhattackdsr->IsLinkCache ())
        {
          addRoute = bhattackdsr->AddRoute_Link (nodeList, ipv4Address);
        }
      else
        {
          addRoute = bhattackdsr->AddRoute (toDestination);
        }

      if (addRoute)
        {
          NS_LOG_DEBUG ("We have added the route and search send buffer for packet with destination " << dst);
          /**
           * dstルートを見つけ、ソースルートオプションヘッダーを構築します
           */
          BhattackdsrOptionSRHeader sourceRoute;
          NS_LOG_DEBUG ("The route length " << nodeList.size ());
          sourceRoute.SetNodesAddress (nodeList);
          sourceRoute.SetSegmentsLeft ((nodeList.size () - 2));
          sourceRoute.SetSalvage (0);
          Ipv4Address nextHop = SearchNextHop (ipv4Address, nodeList); // ネクストホップアドレスを取得する
          NS_LOG_DEBUG ("The nextHop address " << nextHop);
        //  std::cout << "/* rrepを次ホップ */" << '\n';
          if (nextHop == "0.0.0.0")
            {
              bhattackdsr->PacketNewRoute (bhattackdsrP, ipv4Address, dst, protocol);
              return 0;
            }
          PrintVector (nodeList);
          SetRoute (nextHop, ipv4Address);
          // 宛先のルート要求タイマーをキャンセルします
          bhattackdsr->CancelRreqTimer (dst, true);
          /**
           *パケット再試行をスケジュールする
           */
          bhattackdsr->SendPacketFromBuffer (sourceRoute, nextHop, protocol);
        }
      else
        {
          NS_LOG_DEBUG ("Failed to add the route");
          return 0;
        }
    }
  else
    {
      uint8_t length = rrep.GetLength () - 2; //get length-2は、不正な形式のヘッダーチェックに合わせて調整されます
      NS_LOG_DEBUG ("The length of rrep option " << (uint32_t)length);

      if (length % 2 != 0)
        {
          NS_LOG_LOGIC ("Malformed header. Drop!");
          m_dropTrace (packet);
          return 0;
        }
      PrintVector (nodeList);

      /*
       * このノードは中間ノードにすぎませんが、ルートを切断するときに宛先への可能なルートを保存する必要があります
       */
      std::vector<Ipv4Address> routeCopy = nodeList;
      std::vector<Ipv4Address> cutRoute = CutRoute (ipv4Address, nodeList);
      PrintVector (cutRoute);
      if (cutRoute.size () >= 2)
        {
          Ipv4Address dst = cutRoute.back ();
          NS_LOG_DEBUG ("The route destination after cut " << dst);
          BhattackdsrRouteCacheEntry toDestination (/*IP_VECTOR=*/ cutRoute, /*dst=*/ dst, /*expire time=*/ ActiveRouteTimeout);
          NS_ASSERT (cutRoute.front () == ipv4Address);
          bool addRoute = false;
          if (bhattackdsr->IsLinkCache ())
            {
              addRoute = bhattackdsr->AddRoute_Link (nodeList, ipv4Address);
            }
          else
            {
              addRoute = bhattackdsr->AddRoute (toDestination);
            }
          if (addRoute)
            {
              bhattackdsr->CancelRreqTimer (dst, true);
            }
          else
            {
              NS_LOG_DEBUG ("The route not added");
            }
        }
      else
        {
          NS_LOG_DEBUG ("The route is corrupted");
        }
      /*
       * 次ホップアドレスのベクトルを逆検索する
       */

      Ipv4Address nextHop = ReverseSearchNextHop (ipv4Address, routeCopy);
      //std::cout << "/* routecopy.Back */"<< routeCopy.back () << '\n';

    //  std::cout << "/* source */"<< source << '\n';
      NS_ASSERT (routeCopy.back () == source);
      PrintVector (routeCopy);
      NS_LOG_DEBUG ("The nextHop address " << nextHop << " and the source in the route reply " << source);
      /*
       * 返信の送信に使用するルートエントリを設定します
       */
      SetRoute (nextHop, ipv4Address);
      /*
       * この部分は、パケットにbhattackdsrルーティングヘッダーを追加し、返信を送信します
       */
      BhattackdsrRoutingHeader bhattackdsrRoutingHeader;
      bhattackdsrRoutingHeader.SetNextHeader (protocol);

      length = rrep.GetLength ();    // タイプヘッダーを除くrrepヘッダーの長さを取得します
      NS_LOG_DEBUG ("The reply header length " << (uint32_t)length);
      bhattackdsrRoutingHeader.SetPayloadLength (length + 2);
      bhattackdsrRoutingHeader.SetMessageType (1);
      bhattackdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
      bhattackdsrRoutingHeader.SetDestId (GetIDfromIP (targetAddress));
      bhattackdsrRoutingHeader.AddBhattackdsrOption (rrep);
      Ptr<Packet> newPacket = Create<Packet> ();
      newPacket->AddHeader (bhattackdsrRoutingHeader);
      bhattackdsr->SendReply (newPacket, ipv4Address, nextHop, m_ipv4Route);
      isPromisc = false;

    }
  //  std::cout << "/* RREP シリアライズ */" << '\n';
  return rrep.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionSR);

TypeId BhattackdsrOptionSR::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionSR")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionSR> ()
  ;
  return tid;
}

BhattackdsrOptionSR::BhattackdsrOptionSR ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionSR::~BhattackdsrOptionSR ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId BhattackdsrOptionSR::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint8_t BhattackdsrOptionSR::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionSR::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  //ofstream outputfile(fname);
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Address << ipv4Header << (uint32_t)protocol << isPromisc);
  Ptr<Packet> p = packet->Copy ();
  // ルーターのアドレスフィールドの数を取得する
  uint8_t buf[2];
  p->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 2) / 4;
  BhattackdsrOptionSRHeader sourceRoute;
  sourceRoute.SetNumberAddress (numberAddress);
  p->RemoveHeader (sourceRoute);

  ////double proba = 0.01; // 確率（1%）
  ////srand((unsigned)time(NULL)); // 乱数の初期化

  //ソースルートに保存されているルートサイズ
  std::vector<Ipv4Address> nodeList = sourceRoute.GetNodesAddress ();
  uint8_t segsLeft = sourceRoute.GetSegmentsLeft ();
  uint8_t salvage = sourceRoute.GetSalvage ();
  /*
   * IPアドレスからノードを取得し、DSR拡張オブジェクトを取得します
   */
  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
  /*
   * ipv4ヘッダーから送信元および宛先アドレスを取得します
   */
  Ipv4Address srcAddress = ipv4Header.GetSource ();
  Ipv4Address destAddress = ipv4Header.GetDestination ();

  // ノードリストの宛先を取得する
  Ipv4Address destination = nodeList.back ();
  // mノードへの送信を検知
  /*  if (destination == "0.0.0.8")
  {

  }
  */
  /*
   * 無差別受信データパケットの場合、
    * 1.自動ルート短縮が可能かどうかを確認する
    * 2.パッシブ確認応答かどうかを確認する
   */
  if (isPromisc)
    {
      NS_LOG_LOGIC ("We process promiscuous receipt data packet");
      if (ContainAddressAfter (ipv4Address, destAddress, nodeList))
        {
          NS_LOG_LOGIC ("Send back the gratuitous reply");
          bhattackdsr->SendGratuitousReply (source, srcAddress, nodeList, protocol);
        }

      uint16_t fragmentOffset = ipv4Header.GetFragmentOffset ();
      uint16_t identification = ipv4Header.GetIdentification ();

      if (destAddress != destination)
        {
          NS_LOG_DEBUG ("Process the promiscuously received packet");
          bool findPassive = false;
          int32_t nNodes = NodeList::GetNNodes ();
          for (int32_t i = 0; i < nNodes; ++i)
            {
              NS_LOG_DEBUG ("Working with node " << i);

              Ptr<Node> node = NodeList::GetNode (i);
              Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsrNode = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
              // ここの送信元および宛先アドレスは、パケットの実際の送信元および宛先です
              findPassive = bhattackdsrNode->PassiveEntryCheck (packet, source, destination, segsLeft, fragmentOffset, identification, false);
              if (findPassive)
                {
                  break;
                }
            }

          if (findPassive)
            {
              NS_LOG_DEBUG ("We find one previously received passive entry");
              /*
               *IPアドレスからノードを取得し、DSR拡張オブジェクトを取得します
                * srcAddressは、IPヘッダーの送信元アドレスになります
               */
              PrintVector (nodeList);

              NS_LOG_DEBUG ("promisc source " << promiscSource);
              Ptr<Node> node = GetNodeWithAddress (promiscSource);
              Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsrSrc = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
              bhattackdsrSrc->CancelPassiveTimer (packet, source, destination, segsLeft);
            }
          else
            {
              NS_LOG_DEBUG ("Saved the entry for further use");
              bhattackdsr->PassiveEntryCheck (packet, source, destination, segsLeft, fragmentOffset, identification, true);
            }
        }
      //無差別に受信したパケットを安全に終了します
      return 0;
    }
  else
    {

      /*if (GetIDfromIP(ipv4Address) == malicious) {*/
        /* code */
      //  std::cout << "Mノードが受信" << '\n';
      /*outputfile<< "Mノードへsendした回数" << sendtomcount++ << '\n';

      }
      */
      /*
       * ソースルートヘッダーからアドレスの数を取得します
       */
      uint8_t length = sourceRoute.GetLength ();
      uint8_t nextAddressIndex;
      Ipv4Address nextAddress;

      // オプションタイプの値を取得する
      uint32_t size = p->GetSize ();
      uint8_t *data = new uint8_t[size];
      p->CopyData (data, size);
      uint8_t optionType = 0;
      optionType = *(data);
      /// オプションタイプが160の場合、ソースルートの後にACK要求ヘッダーがあることを意味します。
       ///確認応答を送り返す
      if (optionType == 160)
        {
          NS_LOG_LOGIC ("Remove the ack request header and add ack header to the packet");
          // ここでは、前のホップへのackパケットを削除します
          BhattackdsrOptionAckReqHeader ackReq;
          p->RemoveHeader (ackReq);
          uint16_t ackId = ackReq.GetAckId ();
          /*
           * 確認パケットを以前のホップに送り返す
            *ノードリストが空でない場合は、ノードリストから前のホップを見つけ、
            *それ以外の場合は、srcAddressを使用します
           */
          Ipv4Address ackAddress = srcAddress;
          if (GetIDfromIP (ipv4Address) == malicious)
          {
            m_ipv4Route = SetRoute (ackAddress, ipv4Address);
            NS_LOG_DEBUG ("Send back ACK to the earlier hop " << ackAddress << " from us " << ipv4Address);
            bhattackdsr->SendAck (ackId, ackAddress, source, destination, protocol, m_ipv4Route);
            sendACKcount++;
            outputfile << "Send back ACK to the earlier hop " << ackAddress << " from us " << ipv4Address << '\n';
            outputfile << "sendACKした回数" << sendACKcount++ << '\n';
          }
          if (!nodeList.empty ())
            {
              if (segsLeft > numberAddress)   // segmentLeftフィールドは、IPアドレスの合計数を超えてはなりません。
                {
                  NS_LOG_LOGIC ("Malformed header. Drop!");
                  m_dropTrace (packet);
                  return 0;
                }
              // -fstrict-overflow sensitive、バグ1868を参照
              if (numberAddress - segsLeft < 2)   // インデックスが無効です
                {
                  NS_LOG_LOGIC ("Malformed header. Drop!");
                  m_dropTrace (packet);
                  return 0;
                }
              ackAddress = nodeList[numberAddress - segsLeft - 2];
            }
          m_ipv4Route = SetRoute (ackAddress, ipv4Address);
          NS_LOG_DEBUG ("Send back ACK to the earlier hop " << ackAddress << " from us " << ipv4Address);
          bhattackdsr->SendAck (ackId, ackAddress, source, destination, protocol, m_ipv4Route);
          outputfile << "Send back ACK to the earlier hop " << ackAddress << " from us " << ipv4Address << '\n';
          ////sendACKcount++;
        //  std::cout << "sendACKした回数" << sendACKcount++ << '\n';
        }
      /*
       * ACKを送り返した後、セグメントの左の値が0になっているかどうかを確認し、そうであれば、ルートエントリを更新します。
        *およびヘッダー長を返す
       */
      if (segsLeft == 0)
        {
          NS_LOG_DEBUG ("This is the final destination");
          isPromisc = false;
          return sourceRoute.GetSerializedSize ();
        }

      if (length % 2 != 0)
        {
          NS_LOG_LOGIC ("Malformed header. Drop!");
          m_dropTrace (packet);
          return 0;
        }

      if (segsLeft > numberAddress) // segmentLeftフィールドは、IPアドレスの合計数を超えてはなりません。
        {
          NS_LOG_LOGIC ("Malformed header. Drop!");
          m_dropTrace (packet);
          return 0;
        }

      BhattackdsrOptionSRHeader newSourceRoute;
      newSourceRoute.SetSegmentsLeft (segsLeft - 1);
      newSourceRoute.SetSalvage (salvage);
      newSourceRoute.SetNodesAddress (nodeList);
      nextAddressIndex = numberAddress - segsLeft;
      nextAddress = newSourceRoute.GetNodeAddress (nextAddressIndex);
      NS_LOG_DEBUG ("The next address of source route option " << nextAddress << " and the nextAddressIndex: " << (uint32_t)nextAddressIndex << " and the segments left : " << (uint32_t)segsLeft);
      /*
       * ノードリストでターゲットアドレスを取得する
       */
      Ipv4Address targetAddress = nodeList.back ();
      Ipv4Address realSource = nodeList.front ();
      /*
       * 次ホップアドレスのベクターを検索します
       */
      Ipv4Address nextHop = SearchNextHop (ipv4Address, nodeList);
    // std::cout << "次ホップのアドレス = " << nextHop << '\n';
      PrintVector (nodeList);

      if (nextHop == "0.0.0.0")
        {
          NS_LOG_DEBUG ("Before new packet " << *bhattackdsrP);
          bhattackdsr->PacketNewRoute (bhattackdsrP, realSource, targetAddress, protocol);
          return 0;
        }
      if(GetIDfromIP(ipv4Address) == malicious)
        {
          dropcount++;
          outputfile << "/*Mノードにパケットが届いた　ドロップ */"<<dropcount<< "回目"<< '\n';
          //// proba = perc; // 確率（1%）
          //// srand((unsigned)time(NULL)); // 乱数の初期化
          ///if ( (double)rand()/RAND_MAX < proba ) {
          m_dropTrace (packet);
          return 0;
          ////}
        }
      if (ipv4Address == nextHop)
        {
        //  std::cout << "/* 宛先に到達 */" << '\n';
          //マリシャスノードに来たパケットをドロップする

          NS_LOG_DEBUG ("We have reached the destination");
          newSourceRoute.SetSegmentsLeft (0);
          return newSourceRoute.GetSerializedSize ();
        }
      // マルチキャストアドレスを確認します。今のところここに残します
      if (nextAddress.IsMulticast () || destAddress.IsMulticast ())
        {
          m_dropTrace (packet);
          return 0;
        }
      // ルートを設定し、データパケットを転送します
      SetRoute (nextAddress, ipv4Address);
      NS_LOG_DEBUG ("bhattackdsr packet size " << bhattackdsrP->GetSize ());
      bhattackdsr->ForwardPacket (bhattackdsrP, newSourceRoute, ipv4Header, realSource, nextAddress, targetAddress, protocol, m_ipv4Route);

    }
  return sourceRoute.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionRerr);

TypeId BhattackdsrOptionRerr::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionRerr")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionRerr> ()
  ;
  return tid;
}

BhattackdsrOptionRerr::BhattackdsrOptionRerr ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionRerr::~BhattackdsrOptionRerr ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId BhattackdsrOptionRerr::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint8_t BhattackdsrOptionRerr::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionRerr::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  outputfile << ipv4Address << '\n';

  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);
  Ptr<Packet> p = packet->Copy ();
  uint32_t size = p->GetSize ();
  uint8_t *data = new uint8_t[size];
  p->CopyData (data, size);
  uint8_t errorType = *(data + 2);
  /*
   * IPアドレスからノードを取得し、bhattackdsr拡張オブジェクトを取得します
   */
  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
  /*
   * The error serialized size
   */
  uint32_t rerrSize;
  NS_LOG_DEBUG ("The error type value here " << (uint32_t)errorType);
  if (errorType == 1) // unreachable ip address
    {
      /*
       * パケットからルートエラーヘッダーを削除し、エラータイプを取得します
       */
      BhattackdsrOptionRerrUnreachHeader rerrUnreach;
      p->RemoveHeader (rerrUnreach);
      /*
       * エラー宛先アドレスを取得する
       */
      Ipv4Address unreachAddress = rerrUnreach.GetUnreachNode ();
      Ipv4Address errorSource = rerrUnreach.GetErrorSrc ();

      NS_LOG_DEBUG ("The error source is " <<  rerrUnreach.GetErrorDst () << "and the unreachable node is " << unreachAddress);
      if (GetIDfromIP (ipv4Address) == 3)
      {
      outputfile << "rerrmali" << '\n';
    }

      outputfile << "rerr"<< rerrUnreach.GetErrorSrc ()<<" " <<rerrUnreach.GetUnreachNode ()<<" "<< rerrUnreach.GetErrorDst () << '\n';
      /*
       * rerrヘッダーのシリアル化されたサイズを取得します
       */
      rerrSize = rerrUnreach.GetSerializedSize ();
      /*
       * 到達不能ノードアドレスを含むすべてのルートをルートキャッシュから削除します
       */
      Ptr<Node> node = GetNodeWithAddress (ipv4Address);
      bhattackdsr->DeleteAllRoutesIncludeLink (errorSource, unreachAddress, ipv4Address);

      Ptr<Packet> newP = p->Copy ();
      uint32_t serialized = DoSendError (newP, rerrUnreach, rerrSize, ipv4Address, protocol);
      return serialized;
    }
  else
    {
      /*
       * 他の2つのタイプのエラーヘッダー：
        * 1.フロー状態はタイプ固有の情報をサポートしていません
        * 2.オプション番号付きのサポートされていないオプション
        * /
       / *
        *パケットからルートエラーヘッダーを削除し、エラータイプを取得する
       */
      BhattackdsrOptionRerrUnsupportHeader rerrUnsupport;
      p->RemoveHeader (rerrUnsupport);
      rerrSize = rerrUnsupport.GetSerializedSize ();

      NS_UNUSED (rerrSize);
      /// \ todoこれは他の2つのエラーオプション用であり、現時点ではサポートしていません
      // uint32_t serialized = DoSendError (p, rerrUnsupport, rerrSize, ipv4Address, protocol);
      uint32_t serialized = 0;
      return serialized;
    }
}

uint8_t BhattackdsrOptionRerr::DoSendError (Ptr<Packet> p, BhattackdsrOptionRerrUnreachHeader &rerr, uint32_t rerrSize, Ipv4Address ipv4Address, uint8_t protocol)
{
  // ルーターのアドレスフィールドの数を取得する
  uint8_t buf[2];
  p->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 2) / 4;

  //ここで、ソースルートヘッダーを削除し、ネクストホップエラー送信をスケジュールします。
  NS_LOG_DEBUG ("The number of addresses " << (uint32_t)numberAddress);
  BhattackdsrOptionSRHeader sourceRoute;
  sourceRoute.SetNumberAddress (numberAddress);
  p->RemoveHeader (sourceRoute);
  NS_ASSERT (p->GetSize () == 0);
  /*
   * IPアドレスとbhattackdsr拡張オブジェクトからノードを取得します
   */
  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
  /*
   * セグメント左フィールドと次のアドレスを取得します
   */
  uint8_t segmentsLeft = sourceRoute.GetSegmentsLeft ();

  uint8_t length = sourceRoute.GetLength ();
  uint8_t nextAddressIndex;
  Ipv4Address nextAddress;
  /*
   * ルートサイズとエラーターゲットアドレスを取得する
   */
  std::vector<Ipv4Address> nodeList = sourceRoute.GetNodesAddress ();
  Ipv4Address targetAddress = nodeList.back ();
  /*
   * rerrおよびソースルートヘッダーの両方のシリアル化された合計サイズ
   */
  uint32_t serializedSize = rerrSize + sourceRoute.GetSerializedSize ();

  if (length % 2 != 0)
    {
      NS_LOG_LOGIC ("Malformed header. Drop!");
      m_dropTrace (p);
      return 0;
    }

  if (segmentsLeft > numberAddress)
    {
      NS_LOG_LOGIC ("Malformed header. Drop!");
      m_dropTrace (p);
      return 0;
    }
  /*
   * エラーパケットが宛先に到達したとき
   */
  if (segmentsLeft == 0 && targetAddress == ipv4Address)
    {
      NS_LOG_INFO ("This is the destination of the error, send error request");
      bhattackdsr->SendErrorRequest (rerr, protocol);
      return serializedSize;
    }

  // Get the next Router Address
  BhattackdsrOptionSRHeader newSourceRoute;
  newSourceRoute.SetSegmentsLeft (segmentsLeft - 1);
  nextAddressIndex = numberAddress - segmentsLeft;
  nextAddress = sourceRoute.GetNodeAddress (nextAddressIndex);
  newSourceRoute.SetSalvage (sourceRoute.GetSalvage ());
  newSourceRoute.SetNodesAddress (nodeList);
  nextAddress = newSourceRoute.GetNodeAddress (nextAddressIndex);

  ///次のアドレスがマルチキャストかどうかをテストするには
  if (nextAddress.IsMulticast () || targetAddress.IsMulticast ())
    {
      m_dropTrace (p);
      return serializedSize;
    }

  // Set the route entry
  SetRoute (nextAddress, ipv4Address);
  bhattackdsr->ForwardErrPacket (rerr, newSourceRoute, nextAddress, protocol, m_ipv4Route);
  return serializedSize;
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionAckReq);

TypeId BhattackdsrOptionAckReq::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionAckReq")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionAckReq> ()
  ;
  return tid;
}

BhattackdsrOptionAckReq::BhattackdsrOptionAckReq ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionAckReq::~BhattackdsrOptionAckReq ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId BhattackdsrOptionAckReq::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint8_t BhattackdsrOptionAckReq::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionAckReq::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{
  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);
  /*
   * ACKリクエストヘッダー処理の現在の実装は、ソースルートヘッダー処理でコーディングされています。
    * /
   / *
    * ackリクエストヘッダーを削除
   */
  Ptr<Packet> p = packet->Copy ();
  BhattackdsrOptionAckReqHeader ackReq;
  p->RemoveHeader (ackReq);
  /*
   * IPアドレスを持つノードを取得し、より若い拡張機能とルートキャッシュオブジェクトを取得します
   */
  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();

  NS_LOG_DEBUG ("The next header value " << (uint32_t)protocol);

  return ackReq.GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (BhattackdsrOptionAck);

TypeId BhattackdsrOptionAck::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::bhattackdsr::BhattackdsrOptionAck")
    .SetParent<BhattackdsrOptions> ()
    .SetGroupName ("Bhattackdsr")
    .AddConstructor<BhattackdsrOptionAck> ()
  ;
  return tid;
}

BhattackdsrOptionAck::BhattackdsrOptionAck ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

BhattackdsrOptionAck::~BhattackdsrOptionAck ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId BhattackdsrOptionAck::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint8_t BhattackdsrOptionAck::GetOptionNumber () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return OPT_NUMBER;
}

uint8_t BhattackdsrOptionAck::Process (Ptr<Packet> packet, Ptr<Packet> bhattackdsrP, Ipv4Address ipv4Address, Ipv4Address source, Ipv4Header const& ipv4Header, uint8_t protocol, bool& isPromisc, Ipv4Address promiscSource)
{

  NS_LOG_FUNCTION (this << packet << bhattackdsrP << ipv4Address << source << ipv4Header << (uint32_t)protocol << isPromisc);
  /*
   * ACKヘッダーを削除する
   */
  Ptr<Packet> p = packet->Copy ();
  BhattackdsrOptionAckHeader ack;
  p->RemoveHeader (ack);
  /*
   * ACKの送信元および宛先アドレスを取得します
   */
  Ipv4Address realSrc = ack.GetRealSrc ();
  Ipv4Address realDst = ack.GetRealDst ();
  uint16_t ackId = ack.GetAckId ();
  /*
   * IPアドレスを持つノードを取得し、bhattackdsr拡張機能とルートキャッシュオブジェクトを取得します
   */
  Ptr<Node> node = GetNodeWithAddress (ipv4Address);
  Ptr<bhattackdsr::BhattackdsrRouting> bhattackdsr = node->GetObject<bhattackdsr::BhattackdsrRouting> ();
  bhattackdsr->UpdateRouteEntry (realDst);
  /*
   *ackパケットを受信したときにパケット再送信タイマーをキャンセルします
   */
  bhattackdsr->CallCancelPacketTimer (ackId, ipv4Header, realSrc, realDst);
  return ack.GetSerializedSize ();
}

} // namespace bhattackdsr
} // namespace ns3
