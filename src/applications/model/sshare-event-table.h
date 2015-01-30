/*
 * sshare-event-table.h
 *
 *  Created on: 2014年1月6日
 *      Author: huangqi
 */

#ifndef SSHARE_EVENT_TABLE_H_
#define SSHARE_EVENT_TABLE_H_

#include "ns3/ipv4-address.h"
#include "ns3/chord-identifier.h"
#include "ns3/dhash-object.h"
#include <map>


///MD5的结果数据长度
static const size_t ZEN_MD5_HASH_SIZE   = 16;
///SHA1的结果数据长度
static const size_t ZEN_SHA1_HASH_SIZE  = 20;



namespace ZEN_LIB
{


/*!
@brief      求某个内存块的MD5，
@return     unsigned char* 返回的的结果，
@param[in]  buf    求MD5的内存BUFFER指针
@param[in]  size   BUFFER长度
@param[out] result 结果
*/
unsigned char *md5(const unsigned char *buf,
                   size_t size,
                   unsigned char result[ZEN_MD5_HASH_SIZE]);


/*!
@brief      求内存块BUFFER的SHA1值
@return     unsigned char* 返回的的结果
@param[in]  buf    求SHA1的内存BUFFER指针
@param[in]  size   BUFFER长度
@param[out] result 结果
*/
unsigned char *sha1(const unsigned char *buf,
                    size_t size,
                    unsigned char result[ZEN_SHA1_HASH_SIZE]);
};


namespace ns3 {

struct CooperateId {
	uint32_t requestorIp;
	uint32_t processingId;
	uint8_t sequenceNum;
};

/**
 *  \ingroup sshareipv4
 *  \class SShareEventTable
 *  \brief S-Share Event Table
 */
class SShareEventTable : public Object {

public:
	enum EventType {
		QUERY_WAIT_FOR_RESULTS = 1,
		QUERY_PROCESSING = 2,
		COOPERATE_WAITING = 3,
		SUBQUERY_PROCESSING = 4,
	};

	SShareEventTable ();
	virtual ~SShareEventTable ();
    virtual void DoDispose ();

    bool AddCooperationEvent(uint32_t requestorIp,
							uint32_t processingId,
							uint8_t sequenceNum,
							uint32_t nextReceivorIp,
							bool isFinal,
							Ptr<ChordIdentifier> hashKey,
							std::string key,
							uint32_t totalNum);

    uint32_t AddQueryProcessingEvent(std::string sparql,
    							uint32_t sparqlId,
    							uint32_t requestorIp,
    							uint32_t queryId);

    uint32_t AddQueryEvent(Ptr<DHashObject> sparqlObject);

    void RemoveQueryEvent(uint32_t id);

    void RemoveQueryProcessingEvent(uint32_t processingId);

    bool FindCooperationEvent(uint32_t requestorIp,
								uint32_t processingId,
								uint8_t sequenceNum);

    bool RemixCooperationEvent(uint32_t requestorIp,
								uint32_t processingId,
								uint8_t sequenceNum,
								std::string lastKey,
								bool& isFinal,
								std::string& mixedKey,
								uint32_t& nextIp);

    uint32_t GetCooperationNextIp(uint32_t requestorIp,
									uint32_t processingId,
									uint8_t sequenceNum);

    bool RemoveCooperationEvent(uint32_t requestorIp,
    							uint32_t processingId,
    							uint8_t sequenceNum);

    bool ReceiveCooperationRsp(uint32_t processingId,
								uint8_t sequenceNum,
								Ptr<ChordIdentifier>& hashKey,
						    	uint32_t& sparqlId,
						    	uint32_t& requestorIp,
						    	uint32_t& queryId);

    void AddQueryProcessingEventWaitingSeq(uint32_t procId, uint8_t seq);

    bool FindSubqueryEvent(Ptr<ChordIdentifier> key);

    bool AddSubqueryEvent(Ptr<ChordIdentifier> key,
    						uint32_t requestorIp,
    						uint32_t processingId,
    						uint8_t sequenceNum,
    						uint32_t totalNum);

    bool ReceiveSubquery(Ptr<ChordIdentifier> key, bool& subqueryOver);

    std::vector<CooperateId> GetCooperateIdList(Ptr<ChordIdentifier> key);

    bool CooperateHasFinished(uint32_t requestorIp,
								uint32_t processingId,
								uint8_t sequenceNum,
								bool& isFinal,
								std::string& mixedKey,
								uint32_t& nextIp);

    void Clean();


private:
    //Ptr<SShareIpv4> m_sshareApplication;


    struct QueryProcessing {
    	Ptr<ChordIdentifier> hashKey;
    	uint32_t sparqlId;
    	uint32_t requestorIp;
    	uint32_t queryId;
    	std::map<uint8_t,uint8_t> waitingList;
    };

    struct CooperateWaiting {
    	bool isFinal;
    	Ptr<ChordIdentifier> subqueryHashKey;
    	uint32_t nextReceivorIp;
    	std::string key;
    	std::string mixedKey;
    	uint8_t mySeqNum;
    	bool haveHeardLastCooperate;
    };

    struct SubqueryWaiting {
    	uint32_t totalNum;
    	uint32_t count;
    	//std::string content;

    	bool SubqueriesIsOver()
    	{
    		if(count<totalNum)
    			return false;
    		return true;
    	}
    	std::vector<CooperateId> waitingCooperateIdList;
    };

    uint32_t m_queryId;
    uint32_t m_procId;

    typedef std::map<uint32_t, Ptr<DHashObject> > QueryMap;
    QueryMap queryList;

    typedef std::map<uint32_t, QueryProcessing> ProcessingQueryMap;		//key:proccessing id
    ProcessingQueryMap procList;

    typedef std::map<ChordIdentifier, SubqueryWaiting> SubqueryWaitingMap;
    SubqueryWaitingMap subqueryWaitingList;

    typedef std::map<uint32_t, std::map<uint32_t, std::map<uint8_t, CooperateWaiting> > > CooperateWaitingMap;		//ip->procid->seq
    CooperateWaitingMap cooperateWaitingList;

};
}



#endif /* SSHARE_EVENT_TABLE_H_ */
