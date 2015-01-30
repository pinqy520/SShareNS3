/*
 * sshare-connection.cc
 *
 *  Created on: 2013年12月17日
 *      Author: huangqi
 */


#include "ns3/sshare-connection.h"
#include "ns3/log.h"

namespace ns3 {
NS_LOG_COMPONENT_DEFINE ("SShareConnection");

SShareConnection::SShareConnection (Ipv4Address ipAddress, uint16_t port, Ptr<Socket> socket)
{
  m_ipAddress = ipAddress;
  m_port = port;
  m_socket = socket;
  m_txState = TX_IDLE;
  m_rxState = RX_IDLE;
  m_totalTxBytes = 0;
  m_currentTxBytes = 0;
  m_lastActivityTime = Simulator::Now();
}

SShareConnection::SShareConnection ()
{
  m_ipAddress = 0;
  m_port = 0;
  m_socket = 0;
  m_txState = TX_IDLE;
  m_rxState = RX_IDLE;
  m_totalTxBytes = 0;
  m_currentTxBytes = 0;
  m_lastActivityTime = Simulator::Now();
}
SShareConnection::SShareConnection (const SShareConnection &connection)
{
  Ptr<SShareConnection> sShareConnection = const_cast<SShareConnection *>(&connection);
  m_ipAddress = sShareConnection->GetIpAddress();
  m_port = sShareConnection->GetPort();
  m_socket = sShareConnection->GetSocket();
  m_txState = TX_IDLE;
  m_rxState = RX_IDLE;
  m_totalTxBytes = 0;
  m_currentTxBytes = 0;
  m_lastActivityTime = Simulator::Now();
}


SShareConnection::~SShareConnection ()
{
  if (m_socket != 0)
  {
    m_socket->Close();
    m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> > ());
    m_socket = 0;
  }
  m_ipAddress = 0;
  m_port = 0;
  m_txState = TX_IDLE;
  m_rxState = RX_IDLE;
  m_totalTxBytes = 0;
  m_currentTxBytes = 0;
  m_txPacketList.clear();
}

void
SShareConnection::DoDispose ()
{
  if (m_socket != 0)
  {
    m_socket->Close();
    m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> > ());
    m_socket = 0;
  }
  m_ipAddress = 0;
  m_port = 0;
  m_txState = TX_IDLE;
  m_rxState = RX_IDLE;
  m_totalTxBytes = 0;
  m_currentTxBytes = 0;
  m_txPacketList.clear();
}

Ipv4Address
SShareConnection::GetIpAddress()
{
  return m_ipAddress;
}

uint16_t
SShareConnection::GetPort()
{
  return m_port;
}

Ptr<Socket>
SShareConnection::GetSocket()
{
  return m_socket;
}

void
SShareConnection::SendTCPData (Ptr<Packet> packet)
{
	//Add packet to pending tx list
	m_txPacketList.push_back (packet);
	//Set state to transmitting
	if (m_txState == TX_IDLE)
	{
		//Start transmitting
		m_txState = TRANSMITTING;
		m_socket -> SetSendCallback (MakeCallback(&SShareConnection::WriteTCPBuffer, this));
		//Initiate transmission
		WriteTCPBuffer (m_socket, m_socket->GetTxAvailable ());
	}
	return;
}

void
SShareConnection::WriteTCPBuffer (Ptr<Socket> socket, uint32_t txSpace)
{
	m_lastActivityTime = Simulator::Now();
	if (m_totalTxBytes == 0)
	{
		//Start new packet Tx
		m_currentTxBytes = 0;
		if (m_txPacketList.size() == 0)
		{
			m_txState = TX_IDLE;
			return;
		}
		m_currentTxPacket = *(m_txPacketList.begin());
		m_totalTxBytes = m_currentTxPacket->GetSize();
		SShareHeader sShareHeader;
		sShareHeader.SetLength (m_totalTxBytes);
		m_currentTxPacket->AddHeader(sShareHeader);
		m_totalTxBytes = m_currentTxPacket->GetSize();
	}
	uint32_t max_frame_size = 1024;
	uint32_t availTxBytes = std::min (max_frame_size, socket->GetTxAvailable ());
	while(m_currentTxBytes < m_totalTxBytes)
	{
		int amountSent;
		int send_size = std::min (availTxBytes, m_totalTxBytes-m_currentTxBytes);
		amountSent = socket->Send (m_currentTxPacket->CreateFragment(m_currentTxBytes, send_size));
		if(amountSent < 0)
		{
			std::cout << "socket out of range" << std::endl;
			return;
		}
		m_currentTxBytes = m_currentTxBytes + send_size;
	}
	m_txPacketList.erase (m_txPacketList.begin());
	m_totalTxBytes = 0;
	m_currentTxBytes = 0;
}

void
SShareConnection::ReadTCPBuffer (Ptr<Socket> socket)
{
	m_lastActivityTime = Simulator::Now();
	uint32_t availRxBytes = socket->GetRxAvailable();
	Ptr<Packet> packet = socket->Recv(availRxBytes, 0);

	while (availRxBytes > 0)
	{
		Ptr<Packet> messagePacket = AssembleMessage(packet, availRxBytes);
		if (messagePacket != NULL)
		{
			m_recvFn (messagePacket, this);
		}
	}

}

Ptr<Packet>
SShareConnection::AssembleMessage (Ptr<Packet>& packet, uint32_t &availRxBytes)
{
	if (m_rxState == RX_IDLE)
	{
		//Receive new packet
		SShareHeader sShareHeader = SShareHeader ();
		packet->RemoveHeader(sShareHeader);
		availRxBytes = availRxBytes - sShareHeader.GetSerializedSize();
		m_totalRxBytes = sShareHeader.GetLength();
		m_currentRxBytes = 0;
		m_currentRxPacket = Create<Packet> ();
		m_rxState = RECEIVING;
	}
	if ((m_totalRxBytes-m_currentRxBytes) <=  packet->GetSize())
	{
		//Deliver message
		m_currentRxPacket->AddAtEnd(packet->CreateFragment(0, m_totalRxBytes-m_currentRxBytes));
		//remove bytes
		packet->RemoveAtStart (m_totalRxBytes-m_currentRxBytes);
		availRxBytes = availRxBytes - (m_totalRxBytes-m_currentRxBytes);
		m_rxState = RX_IDLE;
		return m_currentRxPacket;
	}
	else
	{
		//concat received packet
		m_currentRxPacket->AddAtEnd (packet);
		m_currentRxBytes += packet->GetSize();
		availRxBytes = 0;
		return NULL;
	}
}

void
SShareConnection::SetRecvCallback (Callback<void, Ptr<Packet>, Ptr<SShareConnection> > recvFn)
{
  m_recvFn = recvFn;
}

Time
SShareConnection::GetLastActivityTime ()
{
  return m_lastActivityTime;
}

//Needed for std::map
bool
operator < (const SShareConnection &connectionL, const SShareConnection &connectionR)
{
  Ptr<SShareConnection> connL = const_cast<SShareConnection *>(&connectionL);
  Ptr<SShareConnection> connR = const_cast<SShareConnection *>(&connectionR);
  if (connL->GetIpAddress() < connL->GetIpAddress())
    return true;
  else if (connL->GetIpAddress() == connL->GetIpAddress())
  {
    if (connL->GetPort() < connR->GetPort())
      return true;
    else
      return false;
  }
  else
    return false;
}

bool
operator == (const SShareConnection &connectionL, const SShareConnection &connectionR)
{
  Ptr<SShareConnection> connL = const_cast<SShareConnection *>(&connectionL);
  Ptr<SShareConnection> connR = const_cast<SShareConnection *>(&connectionR);
  if ((connL->GetIpAddress() == connL->GetIpAddress()) && (connL->GetPort() == connR->GetPort()))
    return true;
  else
    return false;
}

}
