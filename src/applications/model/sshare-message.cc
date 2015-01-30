/*
 * sshare-message.cc
 *
 *  Created on: 2013年12月16日
 *      Author: huangqi
 */


#include "ns3/sshare-message.h"
#include "ns3/dhash-object.h"
#include "ns3/log.h"


namespace ns3 {

NS_LOG_COMPONENT_DEFINE("SShareMessage");

NS_OBJECT_ENSURE_REGISTERED (SShareMessage);
NS_OBJECT_ENSURE_REGISTERED (SShareHeader);

SShareHeader::SShareHeader()
{}

SShareHeader::~SShareHeader()
{}

TypeId
SShareHeader::GetTypeId(void)
{
	static TypeId tid = TypeId ("ns3::SShareHeader").SetParent<Header> ().AddConstructor<SShareHeader> ();
	return tid;
}

TypeId
SShareHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
SShareHeader::GetSerializedSize (void) const
{
  uint32_t size = sizeof (uint32_t);
  return size;
}

void
SShareHeader::Print (std::ostream &os) const
{
  os << "Length: " << m_length;
}

void
SShareHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteHtonU32 (m_length);
}

uint32_t
SShareHeader::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_length = i.ReadNtohU32 ();
  size = sizeof (uint32_t);
  return size;
}

SShareMessage::SShareMessage()
{}

SShareMessage::~SShareMessage()
{}

TypeId
SShareMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SShareMessage")
    .SetParent<Header> ()
    .AddConstructor<SShareMessage> ()
    ;
  return tid;
}

TypeId
SShareMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

uint32_t
SShareMessage::GetSerializedSize (void) const
{
	uint32_t size = sizeof (uint8_t) + sizeof (uint32_t);
	switch (m_messageType)
	{
	case QUERY_REQ:
		size += m_message.queryReq.GetSerializedSize ();
		break;
    case QUERY_RSP:
    	size += m_message.queryRsp.GetSerializedSize ();
    	break;
    case COOPERATE_REQ:
    	size += m_message.cooperateReq.GetSerializedSize ();
    	break;
    case COOPERATE_TRA:
    	size += m_message.cooperateTra.GetSerializedSize ();
    	break;
    case COOPERATE_RSP:
    	size += m_message.cooperateRsp.GetSerializedSize ();
    	break;
    case SUBQUERY_REQ:
    	size += m_message.subqueryReq.GetSerializedSize ();
    	break;
    case SUBQUERY_RSP:
    	size += m_message.subqueryRsp.GetSerializedSize ();
    	break;
    case MESSAGE_RSP:
    	size += m_message.messageRsp.GetSerializedSize ();
    	break;
    default:
    	NS_ASSERT (false);
	}
	return size;
}

void
SShareMessage::Print (std::ostream &os) const
{
	os << "\n***SShareMessage Dump***\n";
	os << "Header:: \n";
	os << "MessageType: " << m_messageType<<"\n";
	os << "TransactionId: " << m_transactionId<<"\n";
	os << "Payload:: \n";
	switch (m_messageType)
	{
	case QUERY_REQ:
		m_message.queryReq.Print (os);
		break;
	case QUERY_RSP:
		m_message.queryRsp.Print (os);
		break;
	case COOPERATE_REQ:
		m_message.cooperateReq.Print (os);
		break;
    case COOPERATE_TRA:
    	m_message.cooperateTra.Print (os);
    	break;
    case COOPERATE_RSP:
    	m_message.cooperateRsp.Print (os);
    	break;
    case SUBQUERY_REQ:
    	m_message.subqueryReq.Print (os);
    	break;
    case SUBQUERY_RSP:
    	m_message.subqueryRsp.Print (os);
    	break;
    case MESSAGE_RSP:
    	m_message.messageRsp.Print (os);
    	break;
    default:
    	break;
	}
	os << "\n***End Of Message***\n";
}

void
SShareMessage::Serialize (Buffer::Iterator start) const
{
	Buffer::Iterator i = start;
	i.WriteU8 (m_messageType);
	i.WriteHtonU32 (m_transactionId);
	switch (m_messageType)
	{
	case QUERY_REQ:
		m_message.queryReq.Serialize(i);
		break;
	case QUERY_RSP:
		m_message.queryRsp.Serialize(i);
  		break;
	case COOPERATE_REQ:
		m_message.cooperateReq.Serialize(i);
		break;
	case COOPERATE_TRA:
		m_message.cooperateTra.Serialize(i);
      	break;
    case COOPERATE_RSP:
      	m_message.cooperateRsp.Serialize(i);
      	break;
    case SUBQUERY_REQ:
      	m_message.subqueryReq.Serialize(i);
      	break;
    case SUBQUERY_RSP:
      	m_message.subqueryRsp.Serialize(i);
      	break;
    case MESSAGE_RSP:
      	m_message.messageRsp.Serialize(i);
      	break;
    default:
      NS_ASSERT (false);
	}
}

uint32_t
SShareMessage::Deserialize (Buffer::Iterator start)
{
	uint32_t size;
	Buffer::Iterator i = start;
	m_messageType = (MessageType) i.ReadU8 ();
	m_transactionId =  i.ReadNtohU32 ();

	size = sizeof (uint8_t) + sizeof (uint32_t);

	switch (m_messageType)
	{
	case QUERY_REQ:
		m_message.queryReq.Deserialize(i);
		break;
	case QUERY_RSP:
		m_message.queryRsp.Deserialize(i);
		break;
	case COOPERATE_REQ:
		m_message.cooperateReq.Deserialize(i);
		break;
	case COOPERATE_TRA:
		m_message.cooperateTra.Deserialize(i);
    	break;
	case COOPERATE_RSP:
    	m_message.cooperateRsp.Deserialize(i);
    	break;
	case SUBQUERY_REQ:
    	m_message.subqueryReq.Deserialize(i);
    	break;
	case SUBQUERY_RSP:
    	m_message.subqueryRsp.Deserialize(i);
    	break;
	case MESSAGE_RSP:
	    m_message.messageRsp.Deserialize(i);
	    break;
    default:
    	NS_ASSERT (false);
	}
	return size;
}

/* Message Payloads */

/* QUERY_REQ */

uint32_t
SShareMessage::QueryReq::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint32_t) + this->sparql->GetSerializedSize();
	return size;
}

void
SShareMessage::QueryReq::Print (std::ostream &os) const
{
	os << "QueryReq: \n";
	os << "Query ID:  " << queryId;
	os << "SPARQL request: " << sparql->GetObject();
}

void
SShareMessage::QueryReq::Serialize (Buffer::Iterator &start) const
{
	start.WriteHtonU32(queryId);
	sparql->Serialize(start);
}

uint32_t
SShareMessage::QueryReq::Deserialize (Buffer::Iterator &start)
{
	this->queryId = start.ReadNtohU32();
	sparql = Create<DHashObject> ();
	sparql->Deserialize(start);
	return GetSerializedSize();
}

/* QUERY_RSP */

uint32_t
SShareMessage::QueryRsp::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint32_t) + this->result->GetSerializedSize();
	return size;
}

void
SShareMessage::QueryRsp::Print (std::ostream &os) const
{
	os << "QueryRsp: \n";
	os << "Query ID:  " << queryId;
	os << "Results Of Sparql Query: " << result->GetObject();
}

void
SShareMessage::QueryRsp::Serialize (Buffer::Iterator &start) const
{
	start.WriteHtonU32(queryId);
	result->Serialize(start);
}

uint32_t
SShareMessage::QueryRsp::Deserialize (Buffer::Iterator &start)
{
	this->queryId = start.ReadNtohU32();
	result = Create<DHashObject> ();
	result->Deserialize(start);
	return GetSerializedSize();
}

/* COOPERATE_REQ */

uint32_t
SShareMessage::CooperateReq::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + this->key->GetSerializedSize();
	return size;
}

void
SShareMessage::CooperateReq::Print (std::ostream &os) const
{
  os << "CooperateReq: \n";
  os << "Sequence Number: " << seqenceNum;
  os << "Is the Final Request:  " << (bool)isFinal;
  os << "Processing ID:  " << processingId;
  os << "Receivor IP:  " << Ipv4Address(receivorIp);
  os << "Key: " << key->GetObject();
}

void
SShareMessage::CooperateReq::Serialize (Buffer::Iterator &start) const
{
	start.WriteU8(this->seqenceNum);
	start.WriteU8(this->isFinal);
	start.WriteHtonU32(processingId);
	start.WriteHtonU32(receivorIp);
	key->Serialize(start);
}

uint32_t
SShareMessage::CooperateReq::Deserialize (Buffer::Iterator &start)
{
	seqenceNum = start.ReadU8();
	isFinal = start.ReadU8();
	this->processingId = start.ReadNtohU32();
	this->receivorIp = start.ReadNtohU32();
	key = Create<DHashObject> ();
	key->Deserialize(start);
	return GetSerializedSize();
}

/* COOPERATE_TRA */

uint32_t
SShareMessage::CooperateTra::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + this->key->GetSerializedSize() + this->recentResult->GetSerializedSize();
	return size;
}

void
SShareMessage::CooperateTra::Print (std::ostream &os) const
{
  os << "CooperateTra: \n";
  os << "Sequence Number: " << seqenceNum;
  os << "Requestor IP:  " << Ipv4Address(requestorIp);
  os << "Processing ID:  " << processingId;
  os << "Key: " << key->GetObject();
  os << "Recent Result: " << recentResult;
}

void
SShareMessage::CooperateTra::Serialize (Buffer::Iterator &start) const
{
	start.WriteU8(this->seqenceNum);
	start.WriteHtonU32(requestorIp);
	start.WriteHtonU32(processingId);
	key->Serialize(start);
	recentResult->Serialize(start);
}

uint32_t
SShareMessage::CooperateTra::Deserialize (Buffer::Iterator &start)
{
	seqenceNum = start.ReadU8();
	this->requestorIp = start.ReadNtohU32();
	this->processingId = start.ReadNtohU32();
	key = Create<DHashObject> ();
	key->Deserialize(start);
	recentResult = Create<DHashObject> ();
	recentResult->Deserialize(start);
	return GetSerializedSize();
}

/* COOPERATE_RSP */

uint32_t
SShareMessage::CooperateRsp::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint8_t) + sizeof(uint32_t) + this->finalResult->GetSerializedSize();
	return size;
}

void
SShareMessage::CooperateRsp::Print (std::ostream &os) const
{
  os << "CooperateRsp: \n";
  os << "Sequence Number: " << seqenceNum;
  os << "Processing ID:  " << processingId;
  os << "Final Result: " << finalResult->GetObject();
}

void
SShareMessage::CooperateRsp::Serialize (Buffer::Iterator &start) const
{
	start.WriteU8(this->seqenceNum);
	start.WriteHtonU32(processingId);
	finalResult->Serialize(start);
}

uint32_t
SShareMessage::CooperateRsp::Deserialize (Buffer::Iterator &start)
{
	seqenceNum = start.ReadU8();
	this->processingId = start.ReadNtohU32();
	finalResult = Create<DHashObject> ();
	finalResult->Deserialize(start);
	return GetSerializedSize();
}

/* SUBQUERY_REQ */

uint32_t
SShareMessage::SubqueryReq::GetSerializedSize(void) const
{
	uint32_t size;
	size = this->key->GetSerializedSize();
	return size;
}

void
SShareMessage::SubqueryReq::Print (std::ostream &os) const
{
  os << "SubqueryReq: \n";
  os << "Key: " << key->GetObject();
}

void
SShareMessage::SubqueryReq::Serialize (Buffer::Iterator &start) const
{
	key->Serialize(start);
}

uint32_t
SShareMessage::SubqueryReq::Deserialize (Buffer::Iterator &start)
{
	key = Create<DHashObject> ();
	key->Deserialize(start);
	return GetSerializedSize();
}

/* SUBQUERY_RSP */

uint32_t
SShareMessage::SubqueryRsp::GetSerializedSize(void) const
{
	uint32_t size;
	size = this->recentResult->GetSerializedSize();
	return size;
}

void
SShareMessage::SubqueryRsp::Print (std::ostream &os) const
{
  os << "SubqueryRsp: \n";
  os << "Recent Result: " << recentResult;
}

void
SShareMessage::SubqueryRsp::Serialize (Buffer::Iterator &start) const
{
	recentResult->Serialize(start);
}

uint32_t
SShareMessage::SubqueryRsp::Deserialize (Buffer::Iterator &start)
{
	recentResult = Create<DHashObject> ();
	recentResult->Deserialize(start);
	return GetSerializedSize();
}

/* MESSAGE_RSP */

uint32_t
SShareMessage::MessageRsp::GetSerializedSize(void) const
{
	uint32_t size;
	size = sizeof(uint8_t);
	return size;
}

void
SShareMessage::MessageRsp::Print (std::ostream &os) const
{
	os << "MessageRsp: \n";
	os << "Status: \n" << status;
}

void
SShareMessage::MessageRsp::Serialize (Buffer::Iterator &start) const
{
	start.WriteU8 (status);
}

uint32_t
SShareMessage::MessageRsp::Deserialize (Buffer::Iterator &start)
{
	status = (Status) start.ReadU8();
	return GetSerializedSize();
}


}
