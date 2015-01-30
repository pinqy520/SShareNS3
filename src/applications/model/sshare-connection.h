/*
 * sshare-connection.h
 *
 *  Created on: 2013年12月9日
 *      Author: huangqi
 */

#ifndef SSHARE_CONNECTION_H_
#define SSHARE_CONNECTION_H_

#include "ns3/socket.h"
#include "ns3/ptr.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "ns3/timer.h"
#include "ns3/callback.h"
#include "ns3/sshare-message.h"
#include <vector>

namespace ns3 {

/**
 *  \ingroup sshareipv4
 *  \class SShareConnection
 *  \brief Class to operate on TCP connection
 *
 */
class SShareConnection : public Object
{

public:
	/**
	 *  \brief Constructor
	 *  \param ipAddress Ipv4Address of remote node
	 *  \param port
	 *  \param socket Ptr to Socket
	 */
	SShareConnection (Ipv4Address ipAddress, uint16_t port, Ptr<Socket> socket);
	SShareConnection ();
	/**
	 *  \brief Copy Constructor
	 *  \param sShareConnection
	 */
	SShareConnection (const SShareConnection &sShareConnection);
	virtual ~SShareConnection ();
	virtual void DoDispose ();

    /**
     *  \returns Ipv4Address of remote host
     */
    Ipv4Address GetIpAddress ();
    /**
     *  \returns port of remote host
     */
    uint16_t GetPort ();
    /**
     *  \returns TCP socket
     */
    Ptr<Socket> GetSocket ();
    /**
     *  \returns Timestamp of last activity on socket
     */
    Time GetLastActivityTime ();

    //TCP methods
    /**
     *  \brief Sends data on open connection
     *  \param packet Ptr to Packet
     */
    void SendTCPData (Ptr<Packet> packet);
    /**
     *  \brief Writes data on socket based on available space info
     *  \param Ptr to Socket
     *  \param txSpace
     */
    void WriteTCPBuffer (Ptr<Socket> socket, uint32_t txSpace);
    /**
     *  \brief Read data from socket
     *  \param socket Ptr to Socket
     *  \param txSpace
     */
    void ReadTCPBuffer (Ptr<Socket> socket);
    /**
     *  \brief Registers Receive Callback function
     *  \param recvFn Callback
     *
     *  This upcall is made whenever complete SShareConnection is received
     */
    void SetRecvCallback (Callback<void, Ptr<Packet>, Ptr<SShareConnection> > recvFn);

private:

    /**
     *  \cond
     */
    enum TxState
    {
    	TX_IDLE = 0,
    	TRANSMITTING = 1,
    };

    enum RxState
    {
    	RX_IDLE = 0,
    	RECEIVING = 1,
    };

    Ipv4Address m_ipAddress;
    uint16_t m_port;
    Ptr<Socket> m_socket;

    Time m_lastActivityTime;

    //TCP assembly/trasnmission buffer handling

    TxState m_txState;
    std::vector<Ptr<Packet> > m_txPacketList;
    Ptr<Packet> m_currentTxPacket;
    //Current packet tx counters
    uint32_t m_totalTxBytes;
    uint32_t m_currentTxBytes;

    RxState m_rxState;
    //rx counters
    uint32_t m_totalRxBytes;
    uint32_t m_currentRxBytes;
    Ptr<Packet> m_currentRxPacket;
    Callback<void, Ptr<Packet>, Ptr<SShareConnection> > m_recvFn;
    /**
     *  \endcond
     */
    //Assembly of rx packet
    /**
     *  \brief Assembles SShareMessage
     *  \param packet Ptr to Packet
     *  \param availRxBytes
     *  \returns Ptr to complete SShareMessage Packet
     */
    Ptr<Packet> AssembleMessage (Ptr<Packet>& packet, uint32_t& availRxBytes);

    //Operators
    friend bool operator < (const SShareConnection &connectionL, const SShareConnection &connectionR);
    friend bool operator == (const SShareConnection &connectionL, const SShareConnection &connectionR);

};

std::ostream& operator<< (std::ostream& os, Ptr<SShareConnection> const &connection);
bool operator < (const SShareConnection &connectionL, const SShareConnection &connectionR);
bool operator == (const SShareConnection &connectionL, const SShareConnection &connectionR);

}


#endif /* SSHARE_CONNECTION_H_ */
