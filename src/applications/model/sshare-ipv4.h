/*
 * sshare-ipv4.h
 *
 *  Created on: 2013年11月29日
 *      Author: huangqi
 *      @CUC
 */

#ifndef SSHARE_IPV4_H_
#define SSHARE_IPV4_H_

#undef  __DEPRECATED

#include <hash_map>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/traced-callback.h"
#include "ns3/timer.h"
#include "ns3/simulator.h"
#include "ns3/socket.h"
#include "ns3/inet-socket-address.h"
#include "ns3/callback.h"
#include "ns3/sshare-transaction.h"
#include "ns3/sshare-connection.h"
#include "ns3/sshare-message.h"
#include "ns3/sshare-event-table.h"
#include "ns3/chord-ipv4.h"
#include "ns3/chord-identifier.h"


namespace __gnu_cxx
{
	template<> struct hash<std::string>
	{
		size_t operator()(const std::string& s) const
		{
			return __stl_hash_string(s.c_str());
		}
	};
}


namespace ns3 {

/**
 *  \ingroup applications
 *  \defgroup chordipv4 ChordIpv4
 */

/**
 *  \ingroup SShareIpv4
 *  \brief Implement of semantic sharing network base on chord.
 *
 *  Provides API for Configuring and Operating Semantic Sharing Network.
 *
 */
class SShareIpv4 : public Application
{
public:
	SShareIpv4();
	virtual ~SShareIpv4();
	static TypeId GetTypeId (void);

	/* Application interface (SShareIpv4 Service User) */

protected:
	virtual void DoDispose (void);
private:
	virtual void StartApplication (void);
	virtual void StopApplication (void);


	bool m_isIndexNode;
	Ptr<ChordIpv4> m_chordApplication;
	//Ptr<ChordNode> m_chordNode;
	Ipv4Address m_bootStrapIp;
	uint16_t m_bootStrapPort;
	Ipv4Address m_localIpAddress;
	uint16_t m_sSharePort;
	Ptr<Socket> m_socket;

	typedef std::map<Ptr<Socket>, Ptr<SShareConnection> > SShareConnectionMap;
	SShareConnectionMap m_sShareConnectionTable;
	typedef std::map<uint32_t, Ptr<SShareTransaction> > SShareTransactionMap;
	SShareTransactionMap m_sShareTransactionTable;

	void SendSShareRequest (Ipv4Address ipAddress, uint16_t port, Ptr<SShareTransaction> sShareTransaction);
	//void SendSShareResponse (Ipv4Address ipAddress, uint16_t port, Ptr<SShareTransaction> sShareTransaction);
	//Connection Layer
	Ptr<SShareConnection> AddConnection (Ptr<Socket> socket, Ipv4Address ipAddress, uint16_t port);
	bool FindConnection (Ptr<Socket> m_socket, Ptr<SShareConnection> &sShareConnection);
	void RemoveConnection (Ptr<Socket> socket);
	bool FindConnection (Ipv4Address ipAddress, uint16_t port, Ptr<SShareConnection>& sShareConnection);

	//Notifications

	void NotifyQueryRequest(Ptr<SShareTransaction> sShareTransaction);
	void NotifyQueryResponse(Ptr<SShareTransaction> sShareTransaction);
	void NotifyCooperateRequest(Ptr<SShareTransaction> sShareTransaction);
	void NotifyCooperateTransmission(Ptr<SShareTransaction> sShareTransaction);
	void NotifyCooperateResponse(Ptr<SShareTransaction> sShareTransaction);
	void NotifyTimeOutFailure(Ptr<SShareTransaction> sShareOldTransaction);
	void SendAgain(Ipv4Address ipaddr, SShareMessage sShareMessage);



	//Packing methods
	void PackQueryReq (uint32_t queryId, Ptr<DHashObject> sparql, SShareMessage& sShareMessage);
	void PackQueryRsp (uint32_t queryId, Ptr<DHashObject> result, SShareMessage& sShareMessage);
	void PackCooperateReq (uint8_t seqenceNum,
							uint8_t isFinal,
							uint32_t processingId,
							uint32_t receivorIp,
							Ptr<DHashObject> key,
							SShareMessage& sShareMessage);
	void PackCooperateTra (uint8_t seqenceNum,
							uint32_t requestorIp,
							uint32_t processingId,
							Ptr<DHashObject> key,
							Ptr<DHashObject> recentResult,
							SShareMessage& sShareMessage);
	void PackCooperateRsp(uint8_t seqenceNum,
							uint32_t processingId,
							Ptr<DHashObject> finalResult,
							SShareMessage& sShareMessage);
	void PackSubqueryReq(Ptr<DHashObject> sShareObject, SShareMessage& sShareMessage);
	void PackSubqueryRsp(Ptr<DHashObject> sShareObject, SShareMessage& sShareMessage);
	void PackMessageRsp(uint32_t transactionId, uint8_t statusTag, SShareMessage& sShareMessage);

	//Processing methods
	void ProcessQueryReq (SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessQueryRsp (SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessCooperateReq (SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessCooperateTra(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessCooperateRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessSubqueryReq(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessSubqueryRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);
	void ProcessMessageRsp(SShareMessage sShareMessage, Ptr<SShareConnection> sShareConnection);

	uint32_t SendSubqueriesRequest(uint32_t ip, Ptr<DHashObject> sparqlContent);
	void SendCooperateRsp(CooperateId cooperateId, uint32_t dataSize);
	void SendCooperateTra(CooperateId cooperateId, Ptr<DHashObject> key,  uint32_t dataSize, uint32_t next_ip);
	void SendSubqueryRsp(uint32_t requestorIp, Ptr<ChordIdentifier> identifier, uint32_t dataSize);
	void SendQueryRsp(uint32_t queryId, uint32_t requestorIp, uint32_t dataSize);

	void AddCooperateProcessingList();



	Time m_inactivityTimeout;
	Timer m_auditConnectionsTimer;

	uint32_t m_transactionId;
	//Callbacks
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_QueryReqFn;
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_QueryRspFn;
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_CooperateReqFn;
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_CooperateRspFn;
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_SubqueryReqFn;
	Callback<void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_SubqueryRspFn;
	Callback <void, uint8_t*, uint8_t, uint8_t*, uint32_t> m_seqretrieveSuccessFn;
	Callback <void, uint8_t*, uint8_t> m_seqretrieveFailureFn;
	Callback <void, std::string> m_goOnProcessingSparqlFn;
	Callback <void, uint32_t> m_packetSendingFn;
	Callback <void> m_processingFn;


public:

	void Query(std::string sparqlQueryString);

	/**
	 *  \brief Set Chord Application callback in SShare.
	 */
	void SetChordCallback();



	void SetSeqRetrieveSuccessCallback (Callback <void, uint8_t*, uint8_t, uint8_t*, uint32_t>);

	void SetSeqRetrieveFailureCallback (Callback <void, uint8_t*, uint8_t>);
	void SetGoOnProcessingSparqlCallback (Callback <void, std::string>);

	void SetPacketSendingCallback(Callback <void, uint32_t>);
	void SetProcessingCallback(Callback <void>);


	void NotifySeqRetrieveSuccess (uint8_t* key, uint8_t keyBytes, uint8_t* object, uint32_t objectBytes);
	void NotifySeqRetrieveFailure (uint8_t* key, uint8_t keyBytes);
	void NotifyGoOnProcessingSparql (std::string sparqlString);
	void NotifyPacketSending(uint32_t packetsize);
	void NotifyProcessing();

	//TCP callbacks
	bool HandleConnectionRequest (Ptr<Socket> socket, const Address& address);
	void HandleAccept (Ptr<Socket> socket, const Address& address);
	void HandleClose (Ptr<Socket> socket);

	//Message processing methods
	void ProcesssShareMessage (Ptr<Packet> packet, Ptr<SShareConnection> sShareConnection);

	//Transaction Layer
	void AddTransaction (Ptr<SShareTransaction> sShareTransaction);
	bool FindTransaction (uint32_t transactionId, Ptr<SShareTransaction>& sShareTransaction);
	void RemoveTransaction (uint32_t transactionId);
	void RemoveActiveTransactions (Ptr<Socket> socket);

	void RemoveSparqlProcess(uint32_t sparqlId, uint32_t queryId, uint32_t requestorIp);

	std::string GetLocalIp();

	struct DataRecord {
		uint32_t size;
		uint64_t time;
	};

	struct keySeq
	{
		keySeq(int n,int m)
		{
			this->No = n;
			this->Seq = m;
		}
		int No;
		int Seq;
	};

	struct prefix
	{
		std::string name;
		std::string value;
	};

	struct SubQuery
	{
		std::string content;
		std::string key;
		std::string sparql;
		int role; 		// triple:-1 ; where:0 ; union:1 ; optional:2 ; filter:3 ; conjunction:4
		std::vector<SubQuery> Sq;
	};

	struct QueryTransformResult
	{
		std::string Query;
		std::string PREFIX;
		SubQuery WHERE;
		std::string Consider;
	};

	struct LocationStorageItem {
		uint32_t seq;
		uint32_t ip;
	};

	typedef __gnu_cxx::hash_map<std::string, std::vector<LocationStorageItem> > LocationMap;
	LocationMap locationTable;


	struct TripleSeqItem {
		std::string content;
		int seq;
		uint32_t indexIp;
		std::vector<uint32_t> sparqlIdList;
		TripleSeqItem()
		{
			seq = -1;
			indexIp = 0;
		}
	};
	void TripleSeqItemSetSeq(int s , TripleSeqItem& t)
	{
		if(t.seq != -1)
		{
			t.seq = s;
		}else{
			t.seq = s;
			for(std::vector<uint32_t>::iterator i = t.sparqlIdList.begin(); i != t.sparqlIdList.end();)
			{
				SparqlOptimizeProcessMap::iterator iterator = sparqlOptimizeProcessTable.find((*i));
				if(iterator != sparqlOptimizeProcessTable.end())
				{
					(*iterator).second.finishSchedule++;
					i++;
				}
				else
					t.sparqlIdList.erase(i++);
			}
		}

	}
	uint32_t m_sparqlId;
	typedef std::map<ChordIdentifier, TripleSeqItem> ItemsHashMap;
	ItemsHashMap itemsList;

	struct SparqlOptimizeProcess {
		QueryTransformResult queryObject;
		uint32_t sparqlId;
		uint8_t tripleCount;
		uint8_t finishSchedule;
		uint32_t queryId;
		uint32_t requestorIp;
		SparqlOptimizeProcess()
		{
			tripleCount = 0;
			finishSchedule = 0;
			sparqlId = 0;
			requestorIp = 0;
			queryId = 0;
		}
		bool IsOver()
		{
			if(tripleCount == finishSchedule)
				return true;
			else
				return false;
		}
	};

	void SparqlOptimizeProcessCleanItems(SparqlOptimizeProcess& s)
	{
		SparqlOptimizeProcessDeleteItemFunc(s.queryObject.WHERE.Sq,s);
	}

	void SparqlOptimizeProcessDeleteItem(std::string key, SparqlOptimizeProcess& s)
	{
		unsigned char* md = (unsigned char*) malloc (20);
		const unsigned char* text = (const unsigned char*) key.c_str();
		ZEN_LIB::sha1 (text , key.length() , md);
		ChordIdentifier identifier(md, 20);
		free (md);
		ItemsHashMap::iterator iterator = itemsList.find(identifier);
		if(iterator == itemsList.end())
			return;

		for(std::vector<uint32_t>::iterator i = (*iterator).second.sparqlIdList.begin(); i != (*iterator).second.sparqlIdList.end();)
		{
			if((*i) == s.sparqlId)
			{
				(*iterator).second.sparqlIdList.erase(i++);
				if((*iterator).second.sparqlIdList.empty())
				{
					itemsList.erase(iterator);
					return;
				}
			}else
			{
				i++;
			}
		}


	}

	void SparqlOptimizeProcessDeleteItemFunc(std::vector<SShareIpv4::SubQuery> s, SparqlOptimizeProcess& so)
	{
		for(uint32_t i=0;i < s.size();i++)
		{
			if(s[i].role == -1)
			{
				SparqlOptimizeProcessDeleteItem(s[i].key, so);
			}else if(s[i].role != 3)
			{
				SparqlOptimizeProcessDeleteItemFunc(s[i].Sq, so);
			}
		}
	}

	void SparqlOptimizeProcessAddItem(std::string content, SparqlOptimizeProcess& s)
	{
		s.tripleCount++;
		unsigned char* md = (unsigned char*) malloc (20);
		const unsigned char* text = (const unsigned char*) content.c_str();
		ZEN_LIB::sha1 (text , content.length() , md);
		ChordIdentifier identifier(md, 20);
		ItemsHashMap::iterator iterator = itemsList.find(identifier);
		if(iterator == itemsList.end())
		{
			TripleSeqItem i;
			i.content = content;
			i.sparqlIdList.push_back(s.sparqlId);
			itemsList.insert(std::make_pair(identifier,i));
		}else
		{
			(*iterator).second.sparqlIdList.push_back(s.sparqlId);
			if((*iterator).second.seq > -1)
				s.finishSchedule++;
		}
		free (md);
	}
	void SparqlOptimizeProcessAddFunc(std::vector<SShareIpv4::SubQuery> s, SparqlOptimizeProcess& so)
	{
		for(uint32_t i=0;i<s.size();i++)
		{
			if(s[i].role == -1)
			{
				SparqlOptimizeProcessAddItem(s[i].key, so);
			}else if(s[i].role != 3)
			{
				SparqlOptimizeProcessAddFunc(s[i].Sq, so);
			}
		}
	}

	void SparqlOptimizeProcessInitItems(SparqlOptimizeProcess& s)
	{
		SparqlOptimizeProcessAddFunc(s.queryObject.WHERE.Sq, s);
	}

	typedef std::map<uint32_t, SparqlOptimizeProcess> SparqlOptimizeProcessMap;
	SparqlOptimizeProcessMap sparqlOptimizeProcessTable;

	typedef __gnu_cxx::hash_map<std::string, DataRecord> DataRecordMap;
	DataRecordMap dataRecordTable;

	SShareEventTable m_eventTable;

public:
	//Periodic processes
	void DoPeriodicAuditConnections ();


	void AddDataRecord(std::string key, uint32_t size, uint64_t time);
	DataRecord GetDataRecord(std::string key);
	void AddLocationTable(std::string key, uint32_t seq, uint32_t ip);
	void SetStore();

	//Sparql Handle
	void SetChordApplication(Ptr<ChordIpv4> chordIpv4);
	bool IsIndexNode();
	void SparqlQuery(std::string sparql, uint32_t reqIp, uint32_t queryId);

	std::vector<SubQuery> AnalizeSparqlContent(std::string cont, std::vector<prefix> plist);
	QueryTransformResult ParserSparqlQuery(std::string sparql);

	QueryTransformResult SparqlGlobalOptimization(QueryTransformResult q);
	std::vector<SubQuery> SortSubqueries(std::vector<SubQuery> s);

	void AddToSortQueue(QueryTransformResult q, uint32_t reqIp, uint32_t queryId);

	void RetriveTripleSequenceSuccess(uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
	void RetriveTripleSequenceFailure(uint8_t* key, uint8_t keyBytes);

	void RetriveTripleSequence();

	void GoOnProcessingSparql(uint32_t id);
	void SendAllCooperationRequest(std::vector<SubQuery> s, uint8_t& group, uint32_t processingId);

	int GetTripleSequence(std::string key);
	Ipv4Address GetTripleIndexIp(std::string key);

	uint32_t GetNextTransactionId ();

};

}

#endif /* SSHARE_IPV4_H_ */
