/*
 * sshare-ipv4.cc
 *
 *  Created on: 2013年12月17日
 *      Author: huangqi
 */



#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/traced-callback.h"
#include "ns3/timer.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/chord-identifier.h"
#include "ns3/sshare-message.h"
#include "ns3/chord-ipv4.h"
#include "ns3/sshare-ipv4.h"


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("SShareIpv4Application");
NS_OBJECT_ENSURE_REGISTERED (SShareIpv4);

TypeId
SShareIpv4::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SShareIpv4")
    .SetParent<Application> ()
    .AddConstructor<SShareIpv4> ()
    .AddAttribute ("BootStrapIp",
                   "IP address of a \"well-known\" Index node (mandatory)",
                   Ipv4AddressValue (),
                   MakeIpv4AddressAccessor (&SShareIpv4::m_bootStrapIp),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("BootStrapPort",
                   "Chord protocol port of bootStrapNode (mandatory)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&SShareIpv4::m_bootStrapPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("LocalIpAddress",
                   "Local IP address (mandatory)",
                   Ipv4AddressValue (),
                   MakeIpv4AddressAccessor (&SShareIpv4::m_localIpAddress),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("ApplicationPort",
                   "SShare Protocol port (mandatory)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&SShareIpv4::m_sSharePort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("ChordEnable",
                   "DHash layer enable flag",
                   BooleanValue (false),
                   MakeBooleanAccessor (&SShareIpv4::m_isIndexNode),
                   MakeBooleanChecker ())
    .AddAttribute ("SShareInactivityTimeout",
                   "Timeout value for closing inactive TCP connection in milli seconds",
                   TimeValue (MilliSeconds (DEFAULT_CONNECTION_INACTIVITY_TIMEOUT)),
                   MakeTimeAccessor (&SShareIpv4::m_inactivityTimeout),
                   MakeTimeChecker ())
     ;
  return tid;
}

SShareIpv4::SShareIpv4 ()
  :m_auditConnectionsTimer(Timer::CANCEL_ON_DESTROY)
{
	NS_LOG_FUNCTION_NOARGS ();
	m_socket = 0;
	m_isIndexNode = false;
	this->m_chordApplication = 0;
	//this->m_sSharePort = 2014;
}

SShareIpv4::~SShareIpv4 ()
{
	NS_LOG_FUNCTION_NOARGS ();
	m_socket = 0;
}

void
SShareIpv4::DoDispose (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  StopApplication();
  Application::DoDispose ();
}

void
SShareIpv4::SetChordApplication(Ptr<ChordIpv4> chordIpv4)
{
	this->m_chordApplication = chordIpv4;
	this->m_isIndexNode = true;
	this->SetChordCallback();
}

bool
SShareIpv4::IsIndexNode()
{
	return this->m_isIndexNode;
}

void
SShareIpv4::StartApplication (void)
{
	NS_LOG_FUNCTION_NOARGS ();
	NS_LOG_INFO("***SShareIpv4 starting on Node: " << GetNode()->GetId()
				<<"\n***Parameters: "
				<<"\n***bootStrapIp: " << m_bootStrapIp
				<<"\n***bootStrapPort: " << m_bootStrapPort
				<<"\n***listeningPort: " << m_sSharePort
				<<"\n***localIp: " << m_localIpAddress
	);
	m_transactionId = 0;
	m_sparqlId = 0;
	if (m_socket == 0)
	{
		TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
		m_socket = Socket::CreateSocket (GetNode(), tid);
	    InetSocketAddress local = InetSocketAddress (m_localIpAddress, m_sSharePort);
	    m_socket->Bind (local);
	    m_socket->SetAcceptCallback (
	              MakeCallback(&SShareIpv4::HandleConnectionRequest, this),
	              MakeCallback(&SShareIpv4::HandleAccept, this));
	}
	else
	{
		m_socket->SetAcceptCallback (
	              MakeCallback(&SShareIpv4::HandleConnectionRequest, this),
	              MakeCallback(&SShareIpv4::HandleAccept, this));
	}
	m_socket->Listen();

	m_auditConnectionsTimer.SetFunction(&SShareIpv4::DoPeriodicAuditConnections, this);
	//Start timers
	m_auditConnectionsTimer.Schedule (m_inactivityTimeout);

}

void
SShareIpv4::StopApplication ()
{
	NS_LOG_FUNCTION_NOARGS ();
	if (m_socket != 0)
	{
		m_socket->SetAcceptCallback (
					MakeNullCallback<bool, Ptr<Socket>, const Address & > (),
					MakeNullCallback<void, Ptr<Socket>, const Address &> ());
	}
	//Cancel Timers
	m_auditConnectionsTimer.Cancel();
}

void
SShareIpv4::Query(std::string sparqlQueryString)
{
	NS_LOG_FUNCTION_NOARGS();
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	unsigned char* md = (unsigned char*) malloc (20);
	const unsigned char* message = (const unsigned char*) sparqlQueryString.c_str();
	ZEN_LIB::sha1 (message , sparqlQueryString.length() , md);

	Ptr<DHashObject> sparqlObject = Create<DHashObject>(md, 20, (uint8_t*)sparqlQueryString.c_str(), sparqlQueryString.length());
	uint32_t queryId = this->m_eventTable.AddQueryEvent(sparqlObject);

	if(this->IsIndexNode())
	{
		this->SparqlQuery(sparqlQueryString, m_localIpAddress.Get(), queryId);
	}
	else
	{
		SShareMessage sShareMessage = SShareMessage ();
		PackQueryReq(queryId, sparqlObject, sShareMessage);
		Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
		sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
		AddTransaction (sShareTransaction);
		this->SendSShareRequest(m_bootStrapIp, this->m_sSharePort, sShareTransaction);
	}

	NS_LOG_INFO ("Scheduling Command Query...");
	free (md);
}


void
SShareIpv4::SetSeqRetrieveSuccessCallback (Callback <void, uint8_t*, uint8_t, uint8_t*, uint32_t> retrieveSuccessFn)
{
	m_seqretrieveSuccessFn = retrieveSuccessFn;
}

void
SShareIpv4::SetSeqRetrieveFailureCallback (Callback <void, uint8_t*, uint8_t> retrieveFailureFn)
{
	m_seqretrieveFailureFn = retrieveFailureFn;
}

void
SShareIpv4::SetGoOnProcessingSparqlCallback (Callback <void, std::string> goOnProcessingSparqlFn)
{
	m_goOnProcessingSparqlFn = goOnProcessingSparqlFn;
}

void
SShareIpv4::SetPacketSendingCallback(Callback <void, uint32_t> packetSendingFn)
{
	m_packetSendingFn = packetSendingFn;
}

void
SShareIpv4::NotifySeqRetrieveSuccess (uint8_t* key, uint8_t keyBytes, uint8_t* object, uint32_t objectBytes)
{
	m_seqretrieveSuccessFn (key, keyBytes, object, objectBytes);
}

void
SShareIpv4::NotifySeqRetrieveFailure (uint8_t* key, uint8_t keyBytes)
{
	m_seqretrieveFailureFn (key, keyBytes);
}

void
SShareIpv4::NotifyGoOnProcessingSparql (std::string sparqlString)
{
	m_goOnProcessingSparqlFn(sparqlString);
}

void
SShareIpv4::NotifyPacketSending(uint32_t packetsize)
{
	m_packetSendingFn (packetsize);
}

void
SShareIpv4::NotifyTimeOutFailure(Ptr<SShareTransaction> sShareOldTransaction)
{
	std::cout << "\nTime Out" << std::endl;
	std::cout << "From:\t" << this->GetLocalIp() << "\t|\t";
	std::cout << "to:\t" << sShareOldTransaction->GetSShareConnection()->GetIpAddress() << std::endl;
	std::cout << "type:\t" << sShareOldTransaction->GetSShareMessage().GetMessageType() << std::endl;

//	std::cout << "Time out and Try again!" << std::endl;
//	SShareMessage sShareMessage = sShareOldTransaction->GetSShareMessage();

//	Simulator::Schedule (MilliSeconds(100),
//						&SShareIpv4::SendAgain,
//						this,
//						sShareOldTransaction->GetSShareConnection()->GetIpAddress(),
//						sShareMessage);
}

void
SShareIpv4::SendAgain(Ipv4Address ipaddr, SShareMessage sShareMessage)
{
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddr, this->m_sSharePort, sShareTransaction);
}



bool
SShareIpv4::HandleConnectionRequest (Ptr<Socket> socket, const Address& address)
{
	//Accept all connections
	return true;
}

void
SShareIpv4::HandleAccept (Ptr<Socket> socket, const Address& address)
{
	InetSocketAddress from = InetSocketAddress::ConvertFrom (address);
	AddConnection (socket, from.GetIpv4(), from.GetPort());
}

void
SShareIpv4::HandleClose (Ptr<Socket> socket)
{
	//Remove all active transactions running on this socket
	RemoveActiveTransactions (socket);
	//Remove from connection list
	RemoveConnection (socket);
}

Ptr<SShareConnection>
SShareIpv4::AddConnection (Ptr<Socket> socket, Ipv4Address ipAddress, uint16_t port)
{
  //Create new connection control block
  Ptr<SShareConnection> sShareConnection = Create<SShareConnection> (ipAddress, port, socket);
  socket->SetRecvCallback (MakeCallback(&SShareConnection::ReadTCPBuffer, sShareConnection));
  sShareConnection->SetRecvCallback(MakeCallback(&SShareIpv4::ProcesssShareMessage, this));

  socket->SetCloseCallbacks (MakeCallback(&SShareIpv4::HandleClose, this),
                             MakeCallback(&SShareIpv4::HandleClose, this));
  //Add new connection to map
  m_sShareConnectionTable.insert (std::make_pair(socket, sShareConnection));
  return sShareConnection;
}

void
SShareIpv4::ProcesssShareMessage (Ptr<Packet> packet, Ptr<SShareConnection> sShareConnection)
{
	SShareMessage sShareMessage = SShareMessage ();
	packet->RemoveHeader (sShareMessage);
	NS_LOG_INFO (sShareMessage);
	switch (sShareMessage.GetMessageType ())
	{
	case SShareMessage::QUERY_REQ:
		ProcessQueryReq (sShareMessage, sShareConnection);
		break;
	case SShareMessage::QUERY_RSP:
		ProcessQueryRsp (sShareMessage, sShareConnection);
		break;
	case SShareMessage::COOPERATE_REQ:
		ProcessCooperateReq (sShareMessage, sShareConnection);
		break;
	case SShareMessage::COOPERATE_TRA:
		ProcessCooperateTra (sShareMessage, sShareConnection);
		break;
	case SShareMessage::COOPERATE_RSP:
		ProcessCooperateRsp (sShareMessage, sShareConnection);
		break;
	case SShareMessage::SUBQUERY_REQ:
		ProcessSubqueryReq (sShareMessage, sShareConnection);
		break;
	case SShareMessage::SUBQUERY_RSP:
		ProcessSubqueryRsp (sShareMessage, sShareConnection);
		break;
	case SShareMessage::MESSAGE_RSP:
		ProcessMessageRsp (sShareMessage, sShareConnection);
		break;
	default:
		break;

  }
}

void
SShareIpv4::ProcessQueryReq(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	Ptr<DHashObject> object = sShareMessage.GetQueryReq().sparql;
	uint32_t id = sShareMessage.GetQueryReq().queryId;
	std::string sparqlString((const char*)(char*)object->GetObject(), object->GetSizeOfObject());
	//Add to processing table "QUERY_PROC"
	this->SparqlQuery(sparqlString, sShareConnection->GetIpAddress().Get(), id);
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Query Request success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::QUERY_REQ_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);

}

void
SShareIpv4::ProcessQueryRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	this->m_eventTable.RemoveQueryEvent(sShareMessage.GetQueryRsp().queryId);
	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::QUERY_RSP_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Query Response success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;
}

void
SShareIpv4::ProcessCooperateReq(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	Ptr<DHashObject> cooperationKey = sShareMessage.GetCooperateReq().key;
	uint8_t cooperationSequenceNum = sShareMessage.GetCooperateReq().seqenceNum;
	uint32_t nextReceivorIp = sShareMessage.GetCooperateReq().receivorIp;
	uint32_t processingId = sShareMessage.GetCooperateReq().processingId;
	bool isFinal = false;
	if(sShareMessage.GetCooperateReq().isFinal)
		isFinal = true;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::COOPERATE_REQ_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);
	//start to process
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Cooperate Request success!" << std::endl;

	std::string sparqlContent((const char*)(char*)cooperationKey->GetObject(),cooperationKey->GetSizeOfObject());
	//std::stringstream hashstream;
	//cooperationKey->GetObjectIdentifier()->Print(hashstream);
	//std::string hashKey;
	//hashstream >> hashKey;
	if(nextReceivorIp == 0 || isFinal)
	{
		nextReceivorIp = sShareConnection->GetIpAddress().Get();
	}

	//lookup processing table
	std::cout << this->GetLocalIp() << std::endl;
	std::cout << sparqlContent << std::endl;
	LocationMap::iterator iter = locationTable.find(sparqlContent);
	if(iter == locationTable.end())
	{
		//false
		return;
	}
	std::vector<LocationStorageItem> storageNodeList = (*iter).second;

	if(m_eventTable.AddCooperationEvent(sShareConnection->GetIpAddress().Get(),
										processingId,
										cooperationSequenceNum,
										nextReceivorIp,
										isFinal,
										cooperationKey->GetObjectIdentifier(),
										sparqlContent,
										storageNodeList.size()))
	{
		for(uint32_t i = 0; i < storageNodeList.size(); i++)
		{
			std::cout << "Subquery Request sendding!" << std::endl;
			SendSubqueriesRequest(storageNodeList[i].ip, cooperationKey);
		}
	}
}

void
SShareIpv4::ProcessCooperateTra(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	uint8_t lastSeqNum = sShareMessage.GetCooperateTra().seqenceNum;
	uint32_t cooperateRequestorIp = sShareMessage.GetCooperateTra().requestorIp;
	uint32_t copperateProcessingId = sShareMessage.GetCooperateTra().processingId;
	Ptr<DHashObject> cooperationKey = sShareMessage.GetCooperateTra().key;
	Ptr<DHashObject> cooperationResult = sShareMessage.GetCooperateTra().recentResult;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::COOPERATE_TRA_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);

	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Cooperate Transmission success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;

	//start to process
	uint8_t thisSeqNum = lastSeqNum + 1;
	if(!this->m_eventTable.FindCooperationEvent(cooperateRequestorIp, copperateProcessingId, thisSeqNum))
		return;

	std::cout << "Cooperate Event is Here!" << std::endl;

	std::string lastKey((const char*)(char*)cooperationKey->GetObject(), cooperationKey->GetSizeOfObject());
	bool isFinal;
	std::string mixedKey;
	uint32_t nextIp;

	if(!this->m_eventTable.RemixCooperationEvent(cooperateRequestorIp, copperateProcessingId, thisSeqNum, lastKey, isFinal, mixedKey, nextIp))
		return;
	std::cout << "Cooperate Event is Over!" << std::endl;

	DataRecordMap::iterator drmIter = dataRecordTable.find(mixedKey);
	uint64_t processingTime;
	uint32_t dataSize;
	if(drmIter == dataRecordTable.end()){
		processingTime = 10;
		dataSize = 100;
	}else{
		processingTime = (*drmIter).second.time;
		dataSize = (*drmIter).second.size;

	}
	std::cout << "Time: " << processingTime << "\t|\t";
	std::cout << "Size: " << dataSize << std::endl;

	CooperateId cooperateId;
	cooperateId.sequenceNum = thisSeqNum;
	cooperateId.processingId = copperateProcessingId;
	cooperateId.requestorIp = cooperateRequestorIp;

	if(isFinal)
	{
		Simulator::Schedule (MilliSeconds(processingTime),
							&SShareIpv4::SendCooperateRsp,
							this,
							cooperateId,
							dataSize);
		//SendCooperateRsp(thisSeqNum, copperateProcessingId, dataSize);
	}
	else
	{
		std::string neverMind("never mind!");
		Ptr<DHashObject> cooperationMixedKey = Create<DHashObject>((uint8_t*)neverMind.c_str(), neverMind.size(), (uint8_t*)mixedKey.c_str(), mixedKey.size());
		Simulator::Schedule (MilliSeconds(processingTime),
							&SShareIpv4::SendCooperateTra,
							this,
							cooperateId,
							cooperationMixedKey,
							dataSize,
							nextIp);

		//SendCooperateTra(thisSeqNum, cooperateRequestorIp, copperateProcessingId ,cooperationMixedKey ,dataSize);
	}

}

void
SShareIpv4::ProcessCooperateRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	uint8_t seqenceNum = sShareMessage.GetCooperateRsp().seqenceNum;
	uint32_t processingId = sShareMessage.GetCooperateRsp().processingId;
	Ptr<DHashObject> finalResult = sShareMessage.GetCooperateRsp().finalResult;

	Ptr<ChordIdentifier> hashKey;
	uint32_t sparqlId;
	uint32_t requestorIp;
	uint32_t queryId;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::COOPERATE_RSP_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);

	//start to process
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Cooperate Response success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;

	if(this->m_eventTable.ReceiveCooperationRsp(processingId, seqenceNum, hashKey, sparqlId, requestorIp, queryId))
	{

		std::stringstream hashstream;
		hashKey->Print(hashstream);
		std::string hashString;
		hashstream >> hashString;
		DataRecordMap::iterator drmIter = dataRecordTable.find(hashString);
		uint64_t processingTime;
		uint32_t dataSize;
		if(drmIter == dataRecordTable.end())
		{
			processingTime = 10;
			dataSize = 100;

		}else{
			processingTime = (*drmIter).second.time;
			dataSize = (*drmIter).second.size;
		}
		std::cout << "Time: " << processingTime << "\t|\t";
		std::cout << "Size: " << dataSize << std::endl;

		Simulator::Schedule (MilliSeconds(processingTime),
								&SShareIpv4::SendQueryRsp,
								this,
								queryId,
								requestorIp,
								dataSize);

		RemoveSparqlProcess(sparqlId, queryId, requestorIp);
		this->m_eventTable.RemoveQueryProcessingEvent(processingId);
	}

}


void
SShareIpv4::ProcessSubqueryReq(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	Ptr<DHashObject> key = sShareMessage.GetSubqueryReq().key;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::SUBQUERY_REQ_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);

	//start to process

	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Subquery Request success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;

	std::stringstream hashstream;
	key->GetObjectIdentifier()->Print(hashstream);
	std::string hashKey;
	hashstream >> hashKey;

	std::cout << hashKey << std::endl;

	DataRecordMap::iterator drmIter = dataRecordTable.find(hashKey);
	uint64_t processingTime;
	uint32_t dataSize;
	if(drmIter == dataRecordTable.end()){
		processingTime = 10;
		dataSize = 100;

	}else{
		processingTime = (*drmIter).second.time;
		dataSize = (*drmIter).second.size;

	}
	std::cout << "Time: " << processingTime << "\t|\t";
	std::cout << "Size: " << dataSize << std::endl;

	Simulator::Schedule (MilliSeconds(processingTime),
						&SShareIpv4::SendSubqueryRsp,
						this,
						sShareConnection->GetIpAddress().Get(),
						key->GetObjectIdentifier(),
						dataSize);
}

void
SShareIpv4::ProcessSubqueryRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	Ptr<DHashObject> recentResult = sShareMessage.GetSubqueryRsp().recentResult;

	//send response back
	Ptr<Packet> packet = Create<Packet> ();
	SShareMessage respMessage = SShareMessage();
	PackMessageRsp (sShareMessage.GetTransactionId(), SShareMessage::SUBQUERY_RSP_REC, respMessage);
	packet->AddHeader(respMessage);
	sShareConnection -> SendTCPData (packet);

	//start to process

	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Subquery Response success!" << std::endl;
	std::cout << this->GetLocalIp() << std::endl;

	bool subqueryIsOver;
	if(this->m_eventTable.ReceiveSubquery(recentResult->GetObjectIdentifier(), subqueryIsOver))
	{
		if(subqueryIsOver)
		{
			std::cout << "Subquery Over!" << std::endl;
			std::vector<CooperateId> coIdList = this->m_eventTable.GetCooperateIdList(recentResult->GetObjectIdentifier());
			for(std::vector<CooperateId>::iterator i = coIdList.begin(); i != coIdList.end();i++ )
			{
				bool isFinal;
				std::string mixedKey;
				uint32_t nextIp;
				if(m_eventTable.CooperateHasFinished( (*i).requestorIp,(*i).processingId, (*i).sequenceNum, isFinal, mixedKey, nextIp))
				{
					DataRecordMap::iterator drmIter = dataRecordTable.find(mixedKey);
					uint64_t processingTime;
					uint32_t dataSize;
					if(drmIter == dataRecordTable.end())
					{
						processingTime = 10;
						dataSize = 100;
					}else
					{
						processingTime = (*drmIter).second.time;
						dataSize = (*drmIter).second.size;
					}
					std::cout << "Time: " << processingTime << "\t|\t";
					std::cout << "Size: " << dataSize << std::endl;
					CooperateId cooperateId = (*i);
					if(isFinal)
					{
						Simulator::Schedule (MilliSeconds(processingTime),
											&SShareIpv4::SendCooperateRsp,
											this,
											cooperateId,
											dataSize);
						//SendCooperateRsp(thisSeqNum, copperateProcessingId, dataSize);
					}
					else
					{
						std::string neverMind("never mind!");
						Ptr<DHashObject> cooperationMixedKey = Create<DHashObject>((uint8_t*)neverMind.c_str(), neverMind.size(), (uint8_t*)mixedKey.c_str(), mixedKey.size());
						Simulator::Schedule (MilliSeconds(processingTime),
											&SShareIpv4::SendCooperateTra,
											this,
											cooperateId,
											cooperationMixedKey,
											dataSize,
											nextIp);

						//SendCooperateTra(thisSeqNum, cooperateRequestorIp, copperateProcessingId ,cooperationMixedKey ,dataSize);
					}
				}
			}
		}
	}
	RemoveTransaction (sShareMessage.GetTransactionId());
}

void
SShareIpv4::ProcessMessageRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection)
{
	Ptr<SShareTransaction> sShareTransaction;
	if (FindTransaction(sShareMessage.GetTransactionId(), sShareTransaction) != true)
	{
		return;
	}
	RemoveTransaction (sShareMessage.GetTransactionId());
}

void
SShareIpv4::SendSubqueryRsp(uint32_t requestorIp, Ptr<ChordIdentifier> identifier, uint32_t dataSize)
{
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Subquery Response sending!" << std::endl;

	Ipv4Address ipaddress(requestorIp);
	std::cout << "From:\t" << this->GetLocalIp() << "\t|\t";
	std::cout << "To:\t" << ipaddress << std::endl;

	SShareMessage sShareMessage = SShareMessage ();
	uint8_t* data = (uint8_t*) malloc (dataSize);
	std::memset(data, 'k', dataSize);
	Ptr<DHashObject> finalResult = Create<DHashObject>(identifier , data, dataSize);

	PackSubqueryRsp(finalResult, sShareMessage);

	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddress, this->m_sSharePort, sShareTransaction);
	free(data);
}

uint32_t
SShareIpv4::SendSubqueriesRequest(uint32_t ip, Ptr<DHashObject> sparqlContent)
{
	Ipv4Address ipaddress(ip);
	SShareMessage sShareMessage = SShareMessage ();
	PackSubqueryReq(sparqlContent, sShareMessage);
	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddress, this->m_sSharePort, sShareTransaction);
	return sShareMessage.GetTransactionId();
}

void
SShareIpv4::SendCooperateRsp(CooperateId cooperateId, uint32_t dataSize)
{
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Cooperate Response sending!" << std::endl;

	SShareMessage sShareMessage = SShareMessage ();
	uint8_t* data = (uint8_t*) malloc (dataSize);
	std::memset(data, 'k', dataSize);
	std::string neverMind("never mind!");
	Ptr<DHashObject> finalResult = Create<DHashObject>((uint8_t*)neverMind.c_str(), neverMind.size(), data, dataSize);
	PackCooperateRsp(cooperateId.sequenceNum, cooperateId.processingId, finalResult, sShareMessage);
	Ipv4Address ipaddress(cooperateId.requestorIp);
	std::cout << "From:\t" << this->GetLocalIp() << "\t|\t";
	std::cout << "To:\t" << ipaddress << std::endl;

	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddress, this->m_sSharePort, sShareTransaction);

	this->m_eventTable.RemoveCooperationEvent(cooperateId.requestorIp, cooperateId.processingId, cooperateId.sequenceNum);
	free(data);
}

void
SShareIpv4::SendCooperateTra(CooperateId cooperateId,
								Ptr<DHashObject> key,
								uint32_t dataSize,
								uint32_t next_ip)
{
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Cooperate transmission sending!" << std::endl;

	SShareMessage sShareMessage = SShareMessage ();
	uint8_t* data = (uint8_t*) malloc (dataSize);
	std::memset(data, 'k', dataSize);
	std::string neverMind("never mind!");
	Ptr<DHashObject> recentResult = Create<DHashObject>((uint8_t*)neverMind.c_str(), neverMind.size(), data, dataSize);
	PackCooperateTra (cooperateId.sequenceNum,
						cooperateId.requestorIp,
						cooperateId.processingId,
						key,
						recentResult,
						sShareMessage);
	Ipv4Address ipaddress(next_ip);
	std::cout << "From:\t" << this->GetLocalIp() << "\t|\t";
	std::cout << "Next:\t" << ipaddress << std::endl;

	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddress, this->m_sSharePort, sShareTransaction);

	this->m_eventTable.RemoveCooperationEvent(cooperateId.requestorIp, cooperateId.processingId, cooperateId.sequenceNum);
	free(data);
}

void
SShareIpv4::SendQueryRsp(uint32_t queryId, uint32_t requestorIp, uint32_t dataSize)
{
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Query Response sending!" << std::endl;
	SShareMessage sShareMessage = SShareMessage ();
	uint8_t* data = (uint8_t*) malloc (dataSize);
	std::memset(data, 'k', dataSize);
	std::string neverMind("never mind!");
	Ptr<DHashObject> finalResult = Create<DHashObject>((uint8_t*)neverMind.c_str(), neverMind.size(), data, dataSize);
	PackQueryRsp(queryId, finalResult, sShareMessage);
	Ipv4Address ipaddress(requestorIp);
	std::cout << "From:\t" << this->GetLocalIp() << "\t|\t";
	std::cout << "To:\t" << ipaddress << std::endl;

	Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
	sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
	AddTransaction (sShareTransaction);
	this->SendSShareRequest(ipaddress, this->m_sSharePort, sShareTransaction);

	free(data);
}

void
SShareIpv4::PackQueryReq (uint32_t queryId, Ptr<DHashObject> sparql, SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::QUERY_REQ);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetQueryReq().queryId = queryId;
	sShareMessage.GetQueryReq().sparql = sparql;
}

void
SShareIpv4::PackQueryRsp (uint32_t queryId, Ptr<DHashObject> result, SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::QUERY_RSP);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetQueryRsp().queryId = queryId;
	sShareMessage.GetQueryRsp().result = result;
}


void
SShareIpv4::PackCooperateReq (uint8_t seqenceNum,
								uint8_t isFinal,
								uint32_t processingId,
								uint32_t receivorIp,
								Ptr<DHashObject> key,
								SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::COOPERATE_REQ);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetCooperateReq().seqenceNum = seqenceNum;
	sShareMessage.GetCooperateReq().isFinal = isFinal;
	sShareMessage.GetCooperateReq().processingId = processingId;
	sShareMessage.GetCooperateReq().receivorIp = receivorIp;
	sShareMessage.GetCooperateReq().key = key;
}

void
SShareIpv4::PackCooperateTra (uint8_t seqenceNum,
								uint32_t requestorIp,
								uint32_t processingId,
								Ptr<DHashObject> key,
								Ptr<DHashObject> recentResult,
								SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::COOPERATE_TRA);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetCooperateTra().seqenceNum = seqenceNum;
	sShareMessage.GetCooperateTra().requestorIp = requestorIp;
	sShareMessage.GetCooperateTra().processingId = processingId;
	sShareMessage.GetCooperateTra().key = key;
	sShareMessage.GetCooperateTra().recentResult = recentResult;
}

void
SShareIpv4::PackCooperateRsp(uint8_t seqenceNum,
								uint32_t processingId,
								Ptr<DHashObject> finalResult,
								SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::COOPERATE_RSP);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetCooperateRsp().seqenceNum = seqenceNum;
	sShareMessage.GetCooperateRsp().processingId = processingId;
	sShareMessage.GetCooperateRsp().finalResult = finalResult;
}

void
SShareIpv4::PackSubqueryReq(Ptr<DHashObject> sShareObject, SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::SUBQUERY_REQ);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetSubqueryReq().key = sShareObject;
}

void
SShareIpv4::PackSubqueryRsp(Ptr<DHashObject> sShareObject, SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::SUBQUERY_RSP);
	sShareMessage.SetTransactionId(this->GetNextTransactionId());
	sShareMessage.GetSubqueryRsp().recentResult = sShareObject;
}

void
SShareIpv4::PackMessageRsp(uint32_t transactionId, uint8_t statusTag, SShareMessage& sShareMessage)
{
	sShareMessage.SetMessageType(SShareMessage::MESSAGE_RSP);
	sShareMessage.SetTransactionId(transactionId);
	sShareMessage.GetMessageRsp().status = statusTag;
}

void
SShareIpv4::AddTransaction (Ptr<SShareTransaction> sShareTransaction)
{
	this->m_sShareTransactionTable.insert(std::make_pair(sShareTransaction->GetSShareMessage().GetTransactionId(), sShareTransaction));
}

bool
SShareIpv4::FindTransaction (uint32_t transactionId, Ptr<SShareTransaction>& sShareTransaction)
{
  SShareTransactionMap::iterator iterator = m_sShareTransactionTable.find (transactionId);
  if (iterator == m_sShareTransactionTable.end())
  {
    return false;
  }
  sShareTransaction = (*iterator).second;
  return true;
}

void
SShareIpv4::RemoveTransaction (uint32_t transactionId)
{
  SShareTransactionMap::iterator iterator = m_sShareTransactionTable.find (transactionId);
  if (iterator == m_sShareTransactionTable.end())
  {
    return;
  }
  m_sShareTransactionTable.erase (iterator);
  return;
}

void
SShareIpv4::RemoveActiveTransactions (Ptr<Socket> socket)
{
  NS_LOG_INFO ("Connection lost, clearing transactions");
  for (SShareTransactionMap::iterator iterator = m_sShareTransactionTable.begin(); iterator != m_sShareTransactionTable.end(); )
  {
    Ptr<SShareTransaction> sShareTransaction = (*iterator).second;
    if (sShareTransaction->GetActiveFlag() && sShareTransaction->GetSShareConnection()->GetSocket() == socket)
    {
      //Report failure and remove
      NotifyTimeOutFailure (sShareTransaction);
      m_sShareTransactionTable.erase (iterator++);
    }
    else
      ++iterator;
  }
}


void
SShareIpv4::SendSShareRequest(Ipv4Address ipAddress, uint16_t port, Ptr<SShareTransaction> sShareTransaction)
{
	Ptr<Packet> packet = Create<Packet> ();
	packet->AddHeader (sShareTransaction->GetSShareMessage());
	if (packet->GetSize())
	{
		//Set activity flag
		sShareTransaction->SetActiveFlag (true);
		//Check for existing connections
		Ptr<SShareConnection> connection;
		if (FindConnection (ipAddress, port, connection) != true)
		{
			//Open new connection
			TypeId tid = TypeId::LookupByName ("ns3::TcpSocketFactory");
			Ptr<Socket> socket = Socket::CreateSocket(this->GetNode(), tid);
			connection = AddConnection (socket, ipAddress, port);
			socket->Bind ();
			socket->Connect (InetSocketAddress (ipAddress, port));
		}
		sShareTransaction->SetSShareConnection (connection);
		NotifyPacketSending(packet->GetSize());
		connection->SendTCPData(packet);
	    return;
	}
}

void
SShareIpv4::DoPeriodicAuditConnections ()
{
	//Remove inactive connections
	for (SShareConnectionMap::iterator iterator = m_sShareConnectionTable.begin(); iterator != m_sShareConnectionTable.end(); )
	{
		Ptr<SShareConnection> sShareConnection = (*iterator).second;
		if ((sShareConnection->GetLastActivityTime().GetMilliSeconds() + m_inactivityTimeout.GetMilliSeconds()) < Simulator::Now().GetMilliSeconds())
		{
			//Remove all active transactions running on this socket
			RemoveActiveTransactions (sShareConnection->GetSocket());
			//Remove from table
			m_sShareConnectionTable.erase (iterator++);
		}
		else
			++iterator;
	}
	//Restart timer
	m_auditConnectionsTimer.Schedule (m_inactivityTimeout);
}

void
SShareIpv4::AddDataRecord(std::string key, uint32_t size, uint64_t time)
{
	DataRecord dataRec;
	dataRec.size = size;
	dataRec.time = time;
	dataRecordTable[key] = dataRec;
}

SShareIpv4::DataRecord
SShareIpv4::GetDataRecord(std::string key)
{
	return dataRecordTable[key];
}

void
SShareIpv4::AddLocationTable(std::string key, uint32_t seq, uint32_t ip)
{
	LocationStorageItem litem;
	litem.ip = ip;
	litem.seq = seq;
	locationTable[key].push_back(litem);
}

void
SShareIpv4::SetStore()
{
	for(LocationMap::iterator i = locationTable.begin(); i != locationTable.end(); i++)
	{
		uint32_t seqnum = 0;
		for(uint32_t j=0; j<(*i).second.size(); j++)
		{
			seqnum += (*i).second[j].seq;
		}
//		std::cout << "storing key:" << std::endl;
//		std::cout <<  (*i).first.c_str() << std::endl;
		unsigned char* md = (unsigned char*) malloc (20);
		const unsigned char* text = (const unsigned char*) (*i).first.c_str();
		ZEN_LIB::sha1 (text , (*i).first.length() , md);
		uint32_t storageData[2] = {this->m_localIpAddress.Get(), seqnum};

		this->m_chordApplication->Insert(md, 20, (uint8_t*)storageData, sizeof(storageData));
//		Simulator::Schedule (MilliSeconds(std::rand()%100), &ChordIpv4::Insert, m_chordApplication, md, 20, (uint8_t*)storageData, sizeof(storageData));
		free (md);
	}
}

std::string
SShareIpv4::GetLocalIp()
{
	std::stringstream ipstream;
	ipstream << this->m_localIpAddress;
	std::string ipString;
	ipstream >> ipString;
	return ipString;
}

void
SShareIpv4::RemoveConnection (Ptr<Socket> socket)
{
	SShareConnectionMap::iterator iterator = m_sShareConnectionTable.find (socket);
	if (iterator == m_sShareConnectionTable.end())
	{
		return;
	}

	m_sShareConnectionTable.erase (iterator);
	return;
}

bool
SShareIpv4::FindConnection (Ipv4Address ipAddress, uint16_t port, Ptr<SShareConnection>& sShareConnection)
{
  for (SShareConnectionMap::iterator iterator = m_sShareConnectionTable.begin(); iterator != m_sShareConnectionTable.end(); iterator++)
  {
    Ptr<SShareConnection> connection = (*iterator).second;
    if (connection->GetIpAddress() == ipAddress && connection->GetPort() == port)
    {
      //Connection found
      sShareConnection = connection;
      return true;
    }
  }
  return false;
}

bool
SShareIpv4::FindConnection (Ptr<Socket> socket, Ptr<SShareConnection>& sShareConnection)
{
	SShareConnectionMap::iterator iterator = m_sShareConnectionTable.find (socket);
  if (iterator == m_sShareConnectionTable.end())
  {
    return false;
  }
  sShareConnection = (*iterator).second;
  return true;
}


void
SShareIpv4::SparqlQuery(std::string sparql, uint32_t reqIp, uint32_t queryId)
{
	AddToSortQueue(ParserSparqlQuery(sparql), reqIp, queryId);
	if(sparqlOptimizeProcessTable[this->m_sparqlId].IsOver())
	{
		GoOnProcessingSparql(m_sparqlId);
	}
	else
	{
		RetriveTripleSequence();
	}
}

std::vector<SShareIpv4::SubQuery>
SShareIpv4::AnalizeSparqlContent(std::string cont, std::vector<prefix> plist)
{
	std::vector<SubQuery> sqlist;
	if(cont == "")
		return sqlist;
	std::string::size_type pos1 = 0, pos2 = 0, pos3 = 0;//pos1:start,pos2:end,pos3:temp
	if(cont[0] == '{')
	{
		SubQuery u1,u2;
		pos3 = cont.find("UNION",0);
		u1.content.assign(cont, 0, pos3);
		u1.key = "";
		u1.role = 4;
		pos2 = u1.content.find('}',pos1);
		while(pos2 != std::string::npos)
		{
			pos1 = pos2+1;
			pos2 = u1.content.find('}',pos1);
		}
		pos2 = pos1-1;
		std::string contentTemp;
		contentTemp.assign(u1.content,1,pos2-1);
		u1.Sq = AnalizeSparqlContent(contentTemp,plist);
		pos1 = cont.find('{',pos3);
		pos2 = cont.size();
		u2.content = cont.assign(pos1,pos2-pos1);
		u2.key = "";
		u2.role = 4;
		pos1 = 1;
		pos2 = u2.content.size()-1;
		contentTemp = "";
		contentTemp.assign(u2.content, 1, pos2-1);
		u2.Sq = AnalizeSparqlContent(contentTemp,plist);
		sqlist.push_back(u1);
		sqlist.push_back(u2);
		return sqlist;
	}
	pos1 = 0;pos2 = 0;pos3 = 0;
	pos1 = cont.find('{',pos1)+1;
	pos2 = cont.find('}',pos1);
	while(pos2 != std::string::npos)
	{
		pos3 = pos2+1;
		pos2 = cont.find('}',pos3);
	}
	if(pos1 != 0)
		cont.assign(cont, pos1, pos3-pos1-1);
	pos3 = cont.find('{',0);
	if(pos3 != std::string::npos)
	{
		SubQuery s1;
		std::string::size_type x1;
		pos1 = pos3;
		s1.role = 1;
		x1 = cont.find("OPTIONAL",0);
		if(x1 != std::string::npos && x1 < pos3)
		{
			pos1 = x1;
			s1.role = 2;
		}
		pos2 = cont.find('}',pos1);
		while(pos2 != std::string::npos)
		{
			pos3 = pos2+1;
			pos2 = cont.find('}',pos3);
		}
		s1.content.assign(cont, pos1,pos3-pos1);
		cont.erase(pos1,pos3-pos1);
		s1.key = "";
		s1.Sq = AnalizeSparqlContent(s1.content, plist);
		sqlist.push_back(s1);
	}
	pos1 = 0;pos2 = 0;pos3 = 0;
	pos1 = cont.find("FILTER",0);
	if(pos1 != std::string::npos)
	{
		pos2 = cont.find(')',pos1);
		while(pos2 != std::string::npos)
		{
			pos3 = pos2+1;
			pos2 = cont.find(')',pos3);
		}
		pos2 = pos3;
		SubQuery s2;
		s2.key = "";
		s2.content.assign(cont, pos1,pos2-pos1);
		cont.erase(pos1,pos2-pos1);
		s2.role = 3;
		sqlist.push_back(s2);
	}
	pos1 = 0;pos2 = 0;pos3 = 0;

	pos3 = cont.size()-1;
	while(pos2 != pos3)
	{
		pos2 = cont.find('.',pos1);
		if( (pos2 == std::string::npos || pos2 > pos3) && pos3 != std::string::npos)
			pos2 = pos3;
		std::string ke;
		ke.assign(cont, pos1,pos2-pos1);
		uint32_t a = 0,b = 0;
		for(a=0;a<ke.size();a++)
			if((ke[a] != ' ')&&(ke[a] != '\n')&&(ke[a] != '\t')&&(ke[a] != '\r'))
				break;
		for(b=ke.size()-1;a<=b;b--)
			if((ke[b] != ' ')&&(ke[b] != '\n')&&(ke[b] != '\t')&&(ke[b] != '\r'))
				break;
		ke.assign(ke, a, b-a+1);
		if(ke!="")
		{
			a=0;
			b=0;
			std::string s,p,o;
			if(ke[a] == '\"')
				b = ke.find('\"',a+1);
			b = ke.find(' ',b);
			s.assign(ke, a,b-a+1);
			a = b+1;
			if(ke[a] == '\"')
				b = ke.find('\"',a+1);
			b = ke.find(' ',a);
			p.assign(ke, a, b-a);
			a = b+1;
			b = ke.size();
			o.assign(ke, a, b-a);
			SubQuery sq;
			sq.key  = "";
			sq.content = "";
			sq.sparql = "";
			for(uint32_t i = 0; i < plist.size(); i++)
			{
				sq.sparql = sq.sparql + "PREFIX " + plist[i].name + " <" + plist[i].value + ">\n";
			}
			sq.sparql = sq.sparql + "CONSTRUCT { " + ke + " } \nWHERE { " + ke + " }";
			sq.content = ke;
			sq.role = -1;
			if(s[0] != '?')
			{
				std::string::size_type x = s.find(':');
				if(x != std::string::npos)
				{
					for(uint32_t u = 0; u<plist.size(); u++)
					{
						std::string::size_type repos = s.find(plist[u].name);
						if(repos != std::string::npos)
						{
							//PrintTest(s);
							s.replace(repos, plist[u].name.size(), plist[u].value);
							//PrintTest(s);
						}
					}
				}
				sq.key = "s:" + s;
			}
			if(p[0] != '?')
			{
				std::string::size_type x = p.find(':');
				if(x != std::string::npos)
				{
					for(uint32_t u = 0; u<plist.size(); u++)
					{
						std::string::size_type repos = p.find(plist[u].name);
						if(repos != std::string::npos)
						{
							//PrintTest(p);
							p.replace(repos, plist[u].name.size(), plist[u].value);
							//PrintTest(p);
						}
					}
				}
				if(sq.key != "")
					sq.key = sq.key + "|";
				sq.key = sq.key + "p:" + p;
			}
			if(o[0] != '?')
			{
				std::string::size_type x = o.find(':');
				if(x != std::string::npos)
				{
					for(uint32_t u = 0; u<plist.size(); u++)
					{
						std::string::size_type repos = o.find(plist[u].name);
						if(repos != std::string::npos)
						{
							//PrintTest(o);
							o.replace(repos, plist[u].name.size(), plist[u].value);
							//PrintTest(o);
						}
					}
				}
				if(sq.key != "")
					sq.key = sq.key + "|";
				sq.key = sq.key + "o:" + o;
				//PrintTest(sq.key);
				std::string::size_type findqute = sq.key.find('\"');
				while(findqute != std::string::npos){
					sq.key.erase(findqute, 1);
					findqute = sq.key.find('\"');
				}

			}
			sqlist.push_back(sq);
		}
		pos1  = pos2+1;
	}
	return sqlist;
}

SShareIpv4::QueryTransformResult
SShareIpv4::ParserSparqlQuery(std::string sparql)
{
	QueryTransformResult qtr;
	if(sparql == "")
		return qtr;
	else
	{
		qtr.Query = sparql;
	}

	//PrintTest(sparql);
	std::vector<prefix> plist;
	std::string::size_type pos1 = 0, pos2 = 0, pos3 = 0;//pos1:start,pos2:end,pos3:temp
	pos1 = sparql.find("PREFIX",pos2);
	while(pos1 != std::string::npos)
	{
		pos1 = sparql.find(' ',pos1);
		pos2 = sparql.find(':',pos1);
		prefix newp;
		newp.name.assign(sparql, pos1+1,pos2-pos1);
		pos1 = sparql.find('<',pos2);
		pos2 = sparql.find('>',pos1);
		newp.value.assign(sparql,pos1+1,pos2-pos1-1);
		plist.push_back(newp);
		pos1 = sparql.find("PREFIX",pos2);
	}
	for(uint32_t i = 0; i < plist.size(); i++)
	{
		qtr.PREFIX = qtr.PREFIX + "PREFIX " + plist[i].name + " <" + plist[i].value + ">\n";
//		qtr.PREFIX.AppendFormat("PREFIX %s %s>\r\n",plist[i].name,plist[i].value);
	}
	pos1 = sparql.find("WHERE",pos2);
	pos2 = sparql.find('}',pos1);
	while(pos2 != std::string::npos)
	{
		pos3 = pos2+1;
		pos2 = sparql.find('}',pos3);
	}
	qtr.WHERE.content.assign(sparql,pos1,pos3-pos1);
	qtr.WHERE.role = 0;
	if(pos3 < sparql.size())
	{
		for(pos1 = pos3; pos1 < sparql.size(); pos1++)
			if((sparql[pos1] != ' ')&&(sparql[pos1] != '\n')&&(sparql[pos1] != '\t')&&(sparql[pos1] != '\r'))
				break;
		for(pos2 = (int)(sparql.size()-1);pos1<=pos2;pos2--)
			if((sparql[pos2] != ' ')&&(sparql[pos2] != '\n')&&(sparql[pos2] != '\t')&&(sparql[pos2] != '\r'))
				break;
		qtr.Consider.assign(sparql, pos1 , pos2-pos1+1);
	}
	qtr.WHERE.Sq = AnalizeSparqlContent(qtr.WHERE.content,plist);
	return qtr;
}

void
SShareIpv4::AddToSortQueue(QueryTransformResult q, uint32_t reqIp, uint32_t queryId)
{
	this->m_sparqlId++;
	SparqlOptimizeProcess s;
	s.sparqlId = this->m_sparqlId;
	s.requestorIp = reqIp;
	s.queryId = queryId;
	s.queryObject = q;
	SparqlOptimizeProcessInitItems(s);
	sparqlOptimizeProcessTable.insert(std::make_pair(s.sparqlId, s));
}

SShareIpv4::QueryTransformResult
SShareIpv4::SparqlGlobalOptimization(SShareIpv4::QueryTransformResult q)
{
	QueryTransformResult qtr;
	qtr.Query = q.Query;
	qtr.PREFIX = q.PREFIX;
	qtr.Consider = q.Consider;
	qtr.WHERE.content = q.WHERE.content;
	qtr.WHERE.key = q.WHERE.key;
	qtr.WHERE.role = q.WHERE.role;
	qtr.WHERE.Sq = SortSubqueries(q.WHERE.Sq);
	return qtr;
}

std::vector<SShareIpv4::SubQuery>
SShareIpv4::SortSubqueries(std::vector<SShareIpv4::SubQuery> s)
{
	std::vector<SubQuery> sq;
	std::vector<keySeq> sort;
	for(uint32_t i=0;i<s.size();i++)
	{
		if(s[i].role == -1)
		{
			int seq = GetTripleSequence(s[i].key);
			keySeq ks(i,seq);
			sort.push_back(ks);
		}
	}
	for(uint32_t i=sort.size();i>0;i--)
	{
		for(uint32_t j=1;j<i;j++)
		{
			if(sort[j-1].Seq>sort[j].Seq)
			{
				keySeq temp = sort[j-1];
				sort[j-1] = sort[j];
				sort[j] = temp;
			}
		}
	}
	for(uint32_t i=0;i<s.size();i++)
	{
		if(s[i].role != -1)
		{
			if(s[i].role == 3)
			{
				sq.push_back(s[i]);
			}
			else
			{
				SubQuery stemp;
				stemp.content = s[i].content;
				stemp.key = s[i].content;
				stemp.role = s[i].role;
				stemp.Sq = SortSubqueries(s[i].Sq);
				sq.push_back(stemp);
			}
		}
	}
	for(uint32_t i=0;i<sort.size();i++)
	{
		int num = sort[i].No;
		sq.push_back(s[num]);
	}
	return sq;
}

int
SShareIpv4::GetTripleSequence(std::string key)
{
	unsigned char* md = (unsigned char*) malloc (20);
	const unsigned char* text = (const unsigned char*) key.c_str();
	ZEN_LIB::sha1 (text , key.length() , md);
	ChordIdentifier identifier(md, 20);
	free (md);
	ItemsHashMap::iterator iterator = itemsList.find(identifier);
	if(iterator == itemsList.end())
		return -1;
	return (*iterator).second.seq;
}

Ipv4Address
SShareIpv4::GetTripleIndexIp(std::string key)
{
	unsigned char* md = (unsigned char*) malloc (20);
	const unsigned char* text = (const unsigned char*) key.c_str();
	ZEN_LIB::sha1 (text , key.length() , md);
	ChordIdentifier identifier(md, 20);
	free (md);
	ItemsHashMap::iterator iterator = itemsList.find(identifier);
	if(iterator == itemsList.end())
		return Ipv4Address::GetZero();
	return Ipv4Address((*iterator).second.indexIp);
}

void
SShareIpv4::GoOnProcessingSparql(uint32_t id)
{
	SparqlOptimizeProcessMap::iterator iterator = sparqlOptimizeProcessTable.find(id);

	if(iterator == sparqlOptimizeProcessTable.end() )
		return;

	if(!(*iterator).second.IsOver())
		return;
	NotifyGoOnProcessingSparql ((*iterator).second.queryObject.Query);
	(*iterator).second.queryObject = SparqlGlobalOptimization((*iterator).second.queryObject);
	uint32_t procId = this->m_eventTable.AddQueryProcessingEvent((*iterator).second.queryObject.Query, id, (*iterator).second.requestorIp, (*iterator).second.queryId);
	uint8_t group = 0;
	SendAllCooperationRequest((*iterator).second.queryObject.WHERE.Sq, group, procId);
//Add to processing table "SUBQUERY_SENT_WAIT_FOR_RESULT"
}

void
SShareIpv4::SendAllCooperationRequest(std::vector<SubQuery> s, uint8_t& group, uint32_t processingId)
{
	uint8_t groupNum = group;
	uint8_t num = 0;
	Ptr<ChordIdentifier> nextIdentifier = 0;
	for(uint32_t i=0;i<s.size();i++)
	{
		if(s[i].role == -1)
		{
			num++;
			SShareMessage sShareMessage = SShareMessage ();
			Ptr<ChordIdentifier> identifier;
			if(nextIdentifier == 0)
			{
				unsigned char* md = (unsigned char*) malloc (20);
				const unsigned char* text = (const unsigned char*) s[i].key.c_str();
				ZEN_LIB::sha1 (text , s[i].key.length() , md);
				identifier = Create<ChordIdentifier>(md, 20);
				free (md);
			}
			else
			{
				identifier = nextIdentifier;
			}
			Ptr<DHashObject> object = Create<DHashObject> (identifier, (uint8_t*)s[i].key.c_str(), s[i].key.size());
			uint32_t nextIp = 0;
			//nextIdentifier->DoDispose();
			for(uint32_t j = i + 1; j < s.size(); j++)
			{
				if(s[j].role == -1)
				{
					unsigned char* md = (unsigned char*) malloc (20);
					const unsigned char* text = (const unsigned char*) s[j].key.c_str();
					ZEN_LIB::sha1 (text , s[j].key.length() , md);
					nextIdentifier = Create<ChordIdentifier>(md, 20);
					free (md);
					nextIp = itemsList[*(PeekPointer(nextIdentifier))].indexIp;
				}
			}
			uint8_t isFinal = 0;
			if(nextIp == 0)
			{
				this->m_eventTable.AddQueryProcessingEventWaitingSeq(processingId, groupNum*10 + num);
				isFinal = 1;
			}
			this->PackCooperateReq(groupNum*10 + num, isFinal, processingId, nextIp, object, sShareMessage);
			Ptr<SShareTransaction> sShareTransaction = Create<SShareTransaction> (sShareMessage.GetTransactionId(), sShareMessage);
			sShareTransaction->SetOriginator(SShareTransaction::SSHARE);
			AddTransaction (sShareTransaction);
			this->SendSShareRequest(Ipv4Address(itemsList[identifier].indexIp), this->m_sSharePort, sShareTransaction);
			std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
			std::cout << "Cooperate Resquset sending!" << std::endl;
			//AddItem(s[i].key);
		}else if(s[i].role != 3)
		{
			group++;
			SendAllCooperationRequest(s[i].Sq, group, processingId);
		}
	}

}

void
SShareIpv4::SetChordCallback()
{

//    chordApplication->SetJoinSuccessCallback (MakeCallback(&ChordRun::JoinSuccess, &chordRun));
//    chordApplication->SetLookupSuccessCallback (MakeCallback(&ChordRun::LookupSuccess, &chordRun));
//    chordApplication->SetLookupFailureCallback (MakeCallback(&ChordRun::LookupFailure, &chordRun));
//    chordApplication->SetTraceRingCallback (MakeCallback(&ChordRun::TraceRing, &chordRun));
//    chordApplication->SetVNodeFailureCallback(MakeCallback(&ChordRun::VNodeFailure, &chordRun));
//    chordApplication->SetVNodeKeyOwnershipCallback(MakeCallback(&ChordRun::VNodeKeyOwnership, &chordRun));
    //DHash configuration:: Needs to be done once but can be overwritten...
//    chordApplication->SetInsertSuccessCallback (MakeCallback(&ChordRun::InsertSuccess, &chordRun));
//    chordApplication->SetInsertFailureCallback (MakeCallback(&ChordRun::InsertFailure, &chordRun));

	m_chordApplication->SetRetrieveSuccessCallback (MakeCallback(&SShareIpv4::RetriveTripleSequenceSuccess, this));
	m_chordApplication->SetRetrieveFailureCallback (MakeCallback(&SShareIpv4::RetriveTripleSequenceFailure, this));
}

void
SShareIpv4::RetriveTripleSequence()
{
    for (ItemsHashMap::iterator iter=itemsList.begin( ); iter != itemsList.end( ); ++iter)
    {
        //cout << (*iter).first << "   " << (*iter).second << endl;
    	if((*iter).second.seq == -1)
    	{
    		ChordIdentifier identifier = (*iter).first;
    		if( m_chordApplication == 0 ){
    			 NS_LOG_ERROR ("Retrive Triple Sequence error!");
    			 return;
    		}
    		m_chordApplication->Retrieve(identifier.GetKey(), identifier.GetNumBytes());
    	}
    }
}

void
SShareIpv4::RetriveTripleSequenceSuccess(uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{
	NotifySeqRetrieveSuccess (key, numBytes, object, objectBytes);
	ChordIdentifier identifier(key, numBytes);
	uint32_t* sequenceResult = (uint32_t*)object;
	ItemsHashMap::iterator iterator = itemsList.find(identifier);
	(*iterator).second.indexIp = sequenceResult[0];
	TripleSeqItemSetSeq(sequenceResult[1], (*iterator).second);
	for(uint32_t i = 0; i < (*iterator).second.sparqlIdList.size(); i++)
	{
		//NS_LOG_INFO ("Go on Success!");
		GoOnProcessingSparql((*iterator).second.sparqlIdList[i]);
	}
}

void
SShareIpv4::RetriveTripleSequenceFailure(uint8_t* key, uint8_t keyBytes)
{
	NotifySeqRetrieveFailure (key, keyBytes);
}

uint32_t
SShareIpv4::GetNextTransactionId ()
{
  return m_transactionId++;
}

void
SShareIpv4::RemoveSparqlProcess(uint32_t sparqlId, uint32_t queryId, uint32_t requestorIp)
{
	SparqlOptimizeProcessMap::iterator iterator = sparqlOptimizeProcessTable.find(sparqlId);
	if( (*iterator).second.queryId == queryId && (*iterator).second.requestorIp == requestorIp )
	{
		SparqlOptimizeProcessCleanItems((*iterator).second);
		sparqlOptimizeProcessTable.erase(iterator);
	}
}

}
