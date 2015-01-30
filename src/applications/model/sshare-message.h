/*
 * sshare-message.h
 *
 *  Created on: 2013年12月9日
 *      Author: huangqi
 */

#ifndef SSHARE_MESSAGE_H_
#define SSHARE_MESSAGE_H_

#include <vector>
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/assert.h"
#include "ns3/chord-identifier.h"
#include "ns3/chord-node.h"
#include "ns3/dhash-object.h"

namespace ns3 {

/**
 *  \ingroup sshareipv4
 *  \class SShareHeader
 *  \brief A small class to pack/unpack length header
 */
class SShareHeader : public Header{
public:
	SShareHeader ();
  virtual ~SShareHeader ();

  void SetLength (uint32_t length)
  {
    m_length = length;
  }
  uint32_t GetLength (void) const
  {
    return m_length;
  }

private:
  uint32_t m_length;

public:
  static TypeId GetTypeId (void);
  TypeId GetInstanceTypeId (void) const;
  void Print (std::ostream &os) const;
  uint32_t GetSerializedSize (void) const;
  /**
   *  \brief Packs length of SShareMessage
   *  \verbatim
      Packed Structure:

      SShareHeader:
      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |               |
      |               |
      |    length     |
      |               |
      +-+-+-+-+-+-+-+-+
      \endverbatim
   *
   */
  void Serialize (Buffer::Iterator start) const;
  uint32_t Deserialize (Buffer::Iterator start);
};

/**
 * \ingroup sshareipv4
 * \class SShareMessage
 * \brief Class to pack/unpack SShare Protocol Messages.
 */
class SShareMessage : public Header {
public:
  enum MessageType {
    QUERY_REQ = 1,
    QUERY_RSP = 2,
    COOPERATE_REQ = 3,
    COOPERATE_TRA = 4,
    COOPERATE_RSP = 5,
    SUBQUERY_REQ = 6,
    SUBQUERY_RSP = 7,
    MESSAGE_RSP = 8,
  };

  enum Status {
	QUERY_REQ_REC = 1,
	QUERY_RSP_REC = 2,
	COOPERATE_REQ_REC = 3,
	COOPERATE_TRA_REC = 4,
	COOPERATE_RSP_REC = 5,
	SUBQUERY_REQ_REC = 6,
	SUBQUERY_RSP_REC = 7,
	OTHER_REC = 8,
  };


  SShareMessage ();
  virtual ~SShareMessage ();


  /**
   *  \brief Sets message type
   *  \param messageType message type
   */

  void SetMessageType (MessageType messageType)
  {
    m_messageType = messageType;
  }
  /**
   *  \returns message type
   */
  MessageType GetMessageType () const
  {
    return m_messageType;
  }
  /**
   *  \brief Sets transaction Id
   *  \param transactionId transaction Id of request
   */

  void SetTransactionId (uint32_t transactionId)
  {
    m_transactionId = transactionId;
  }
  /**
   *  \returns transaction Id
   */

  uint32_t GetTransactionId () const
  {
    return m_transactionId;
  }

private:
  /**
   *  \cond
   */
  MessageType m_messageType;
  uint32_t m_transactionId;
  /**
   *  \endcond
   */

public:
    static TypeId GetTypeId (void);
    TypeId GetInstanceTypeId (void) const;
    /**
     *  \brief Prints SShareMessage
     *  \param os Output Stream
     */
    void Print (std::ostream &os) const;
    /**
     *  \returns Size in bytes of packed SShareMessage
     */
    uint32_t GetSerializedSize (void) const;

    /**
      *  \brief Packs SShareMessage
      *  \param start Buffer::Iterator
      *
      *  \verbatim
         Packed Structure:

         SShareMessage:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |  messageType  |
         +-+-+-+-+-+-+-+-+
         |               |
         |               |
         | transactionId |
         |               |
         +-+-+-+-+-+-+-+-+
         |    Payload    |
         +-+-+-+-+-+-+-+-+

         QUERY_REQ Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |               |
         |               |
         |    Query ID   |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |
         :    SPARQL     :
         |               |
         +-+-+-+-+-+-+-+-+

         QUERY_RSP Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |               |
         |               |
         |    Query ID   |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |
         :    Result     :
         |     DATA      |
         +-+-+-+-+-+-+-+-+

         COOPERATE_REQ Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         | Sequence num  |
         +-+-+-+-+-+-+-+-+
         |   Is Final    |
		 +-+-+-+-+-+-+-+-+
         |               |
         |   Cooperate   |
         | Processing ID |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |
         |               |
         |  ReceiverIp   |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |    |-- ChordIdentifier:	SHA1(key)
         :   KeyObject   :  --|
         |               |    |-- Content:			SPARQL
         +-+-+-+-+-+-+-+-+

         COOPERATE_TRA Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         | Sequence num  |
         +-+-+-+-+-+-+-+-+
         |               |
         |   Cooperate   |
         | Requestor IP  |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |
         |   Cooperate   |
         | Processing ID |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |    |-- ChordIdentifier:	xxx
         :   KeyObject   :  --|
         |               |    |-- Content:			LastKey + SelfKey
         +-+-+-+-+-+-+-+-+
         |               |
         :     Recent    :
         |     result    |
         +-+-+-+-+-+-+-+-+

         COOPERATE_RSP Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         | Sequence num  |
		 +-+-+-+-+-+-+-+-+
         |               |
         |   Cooperate   |
         | Processing ID |
         |               |
         +-+-+-+-+-+-+-+-+
         |               |
         :  Final Result :
         |               |
         +-+-+-+-+-+-+-+-+

         SUBQUERY_REQ Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |               |    |-- ChordIdentifier:	SHA1(key)
         :   KeyObject   :  --|
         |               |    |-- Content:			SPARQL
         +-+-+-+-+-+-+-+-+

         SUBQUERY_RSP Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |               |    |-- ChordIdentifier:	SHA1(key)
         : ResultsObject :  --|
         |               |    |-- Content:			Results
         +-+-+-+-+-+-+-+-+

         MESSAGE_RSP Payload:
         0 1 2 3 4 5 6 7 8
         +-+-+-+-+-+-+-+-+
         |               |
         :     Status    :
         |               |
         +-+-+-+-+-+-+-+-+

         \endverbatim

      */
    void Serialize (Buffer::Iterator start) const;
    /**
     *  \brief Unpacks SShareMessage
     *  \param start Buffer::Iterator
     */
    uint32_t Deserialize (Buffer::Iterator start);

    struct QueryReq
    {
    	uint32_t queryId;
    	Ptr<DHashObject> sparql;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };

    struct QueryRsp
    {
    	uint32_t queryId;
    	Ptr<DHashObject> result;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };
    struct CooperateReq
    {
    	uint8_t seqenceNum;
    	uint8_t isFinal;
    	uint32_t processingId;
    	uint32_t receivorIp;
    	Ptr<DHashObject> key;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };
    struct CooperateTra
    {
    	uint8_t seqenceNum;
    	uint32_t requestorIp;
    	uint32_t processingId;
    	Ptr<DHashObject> key;
    	Ptr<DHashObject> recentResult;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };
    struct CooperateRsp
    {
    	uint8_t seqenceNum;
    	uint32_t processingId;
    	Ptr<DHashObject> finalResult;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };
    struct SubqueryReq
    {
    	Ptr<DHashObject> key;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };

    struct SubqueryRsp
    {
    	Ptr<DHashObject> recentResult;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };

    struct MessageRsp
    {
    	uint8_t status;
    	void Print (std::ostream &os) const;
    	uint32_t GetSerializedSize (void) const;
    	void Serialize (Buffer::Iterator &start) const;
    	uint32_t Deserialize (Buffer::Iterator &start);
    };


private:
    struct
    {
    	QueryReq queryReq;
    	QueryRsp queryRsp;
    	CooperateReq cooperateReq;
    	CooperateTra cooperateTra;
    	CooperateRsp cooperateRsp;
    	SubqueryReq subqueryReq;
    	SubqueryRsp subqueryRsp;
    	MessageRsp messageRsp;
    } m_message;
public:
    /**
     *  \returns QueryReq structure
     */
    QueryReq& GetQueryReq ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = QUERY_REQ;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == QUERY_REQ);
    	}
    	return m_message.queryReq;
    }
    /**
     *  \returns QueryRsp structure
     */
    QueryRsp& GetQueryRsp ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = QUERY_RSP;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == QUERY_RSP);
    	}
    	return m_message.queryRsp;
    }
    /**
     *  \returns CooperateReq structure
     */
    CooperateReq& GetCooperateReq ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = COOPERATE_REQ;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == COOPERATE_REQ);
    	}
    	return m_message.cooperateReq;
    }
    /**
     *  \returns CooperateTra structure
     */
    CooperateTra& GetCooperateTra ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = COOPERATE_TRA;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == COOPERATE_TRA);
    	}
    	return m_message.cooperateTra;
    }
    /**
     *  \returns CooperateRsp structure
     */
    CooperateRsp& GetCooperateRsp ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = COOPERATE_RSP;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == COOPERATE_RSP);
    	}
    	return m_message.cooperateRsp;
    }
    /**
     *  \returns SubqueryReq structure
     */
    SubqueryReq& GetSubqueryReq ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = SUBQUERY_REQ;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == SUBQUERY_REQ);
    	}
    	return m_message.subqueryReq;
    }
    /**
     *  \returns SubqueryRsp structure
     */
    SubqueryRsp& GetSubqueryRsp ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = SUBQUERY_RSP;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == SUBQUERY_RSP);
    	}
    	return m_message.subqueryRsp;
    }

    /**
     *  \returns MessageRsp structure
     */
    MessageRsp& GetMessageRsp ()
    {
    	if (m_messageType == 0)
    	{
    		m_messageType = MESSAGE_RSP;
    	}
    	else
    	{
    		NS_ASSERT (m_messageType == MESSAGE_RSP);
    	}
    	return m_message.messageRsp;
    }

}; //class SShareMessage

static inline std::ostream& operator<< (std::ostream& os, const SShareMessage & message)
{
  message.Print (os);
  return os;
}

} //namespace ns3



#endif /* SSHARE_MESSAGE_H_ */
