/*
 * sshare-ipv4-helper.h
 *
 *  Created on: 2013年12月16日
 *      Author: huangqi
 */

#ifndef SSHARE_IPV4_HELPER_H_
#define SSHARE_IPV4_HELPER_H_

#include <stdint.h>
#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/ipv4-address.h"

namespace ns3 {

/* Helper class to install SShare protocol on a ns-3 node */

class SShareIpv4Helper
{
public:

    /* Constructor(s) */

    /**
     * \brief Creates SShareIpv4 layer without DHash Layer
     * \param bootStrapIp Ipv4 Address of a known node in chord network
     * \param bootStrapPort Port of known boot strap node
     * \param localIpAddress Local Ipv4 to use with chord protocol. This allows multi-homing functionality
     * \param applicationPort Port used by application running on top of Chord. This port will be resolved during lookup.
     */
	SShareIpv4Helper(Ipv4Address bootStrapIp, uint16_t bootStrapPort, Ipv4Address localIpAddress, uint16_t applicationPort, bool isIndex);

    /**
     * Record an attribute to be set in each Application after it is is created.
     *
     * \param name the name of the attribute to set
     * \param value the value of the attribute to set
     */
    void SetAttribute(std::string name, const AttributeValue &value);

    /**
     * Create a ChordIpv4 Application on the specified Node.
     *
     * \param node The node on which to create the Application.  The node is
     *             specified by a Ptr<Node>.
     *
     * \returns An ApplicationContainer holding the Application created,
     */
    ApplicationContainer Install (Ptr<Node> node) const;

    /**
     * Create a ChordIpv4 Application on specified node
     *
     * \param nodeName The node on which to create the application.  The node
     *                 is specified by a node name previously registered with
     *                 the Object Name Service.
     *
     * \returns An ApplicationContainer holding the Application created.
     */
    ApplicationContainer Install (std::string nodeName) const;

    /**
     * \param c The nodes on which to create the Applications.  The nodes
     *          are specified by a NodeContainer.
     *
     * Create one ChordIpv4 Application on each of the Nodes in the
     * NodeContainer.
     *
     * \returns The applications created, one Application per Node in the
     *          NodeContainer.
     */
    ApplicationContainer Install (NodeContainer c) const;

  private:
/**
 *  \internal
 */
    Ptr<Application> InstallPriv (Ptr<Node> node) const;
    ObjectFactory m_factory;

};

}



#endif /* SSHARE_IPV4_HELPER_H_ */
