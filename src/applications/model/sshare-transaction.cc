/*
 * sshare-transaction.cc
 *
 *  Created on: 2013年12月17日
 *      Author: huangqi
 */


#include "ns3/sshare-transaction.h"

namespace ns3 {

SShareTransaction::SShareTransaction (uint32_t transactionId, SShareMessage sShareMessage)
{
  m_transactionId = transactionId;
  m_sShareMessage = sShareMessage;
  m_activeFlag = false;
}

SShareTransaction::~SShareTransaction()
{}

void
SShareTransaction::DoDispose()
{
}

void
SShareTransaction::SetActiveFlag (bool activeFlag)
{
  m_activeFlag = activeFlag;
}

uint32_t
SShareTransaction::GetTransactionId ()
{
  return m_transactionId;
}

SShareMessage
SShareTransaction::GetSShareMessage ()
{
  return m_sShareMessage;
}

bool
SShareTransaction::GetActiveFlag()
{
  return m_activeFlag;
}

Ptr<SShareConnection>
SShareTransaction::GetSShareConnection ()
{
  return m_sShareConnection;
}

SShareTransaction::Originator
SShareTransaction::GetOriginator ()
{
  return m_originator;
}

void
SShareTransaction::SetOriginator (SShareTransaction::Originator originator)
{
  m_originator = originator;
}
void
SShareTransaction::SetSShareConnection (Ptr<SShareConnection> dHashConnection)
{
	m_sShareConnection = dHashConnection;
}

}

