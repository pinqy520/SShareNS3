/*
 * sshare-transaction.h
 *
 *  Created on: 2013年12月9日
 *      Author: huangqi
 */

#ifndef SSHARE_TRANSACTION_H_
#define SSHARE_TRANSACTION_H_

#include "ns3/object.h"
#include "ns3/timer.h"
#include "ns3/sshare-message.h"
#include "ns3/sshare-connection.h"

namespace ns3 {

class SShareTransaction : public Object {

public:

  enum Originator {
    CHORD = 1,
    SSHARE = 2,
  };

  /**
   *  \brief Constructor
   *  \param transactionId
   *  \param sShareMessage SShareMessage
   */
  SShareTransaction (uint32_t transactionId, SShareMessage sShareMessage);
  virtual ~SShareTransaction ();
  virtual void DoDispose ();
  //Storage
  //Retrieval
  /**
   *  \returns transactionId
   */
  uint32_t GetTransactionId ();
  /**
   *  \returns SShareMessage
   */
  SShareMessage GetSShareMessage ();
  /**
   *  \brief Set flag to mark transaction as active
   */
  void SetActiveFlag (bool activeFlag);
  /**
   *  \brief Set Connection on which transaction is running
   */
  void SetSShareConnection (Ptr<SShareConnection> sShareConnection);
  /**
   *  \brief Set originator of transaction
   */
  void SetOriginator (SShareTransaction::Originator originator);
  /**
   *  \returns SShareTransaction::Originator
   */
  SShareTransaction::Originator GetOriginator ();
  /**
   *  \returns Active flag
   */
  bool GetActiveFlag ();
  /**
   *  \returns Ptr to SShareConnection
   */
  Ptr<SShareConnection> GetSShareConnection ();
private:
  /**
   *  \cond
   */
  uint32_t m_transactionId;
  bool m_activeFlag;
  SShareMessage m_sShareMessage;
  Ptr<SShareConnection> m_sShareConnection;
  SShareTransaction::Originator m_originator;
  /**
   *  \endcond
   */
};

}



#endif /* SSHARE_TRANSACTION_H_ */
