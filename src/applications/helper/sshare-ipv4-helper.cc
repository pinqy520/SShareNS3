/*
 * sshare-ipv4-helper.cc
 *
 *  Created on: 2013年12月16日
 *      Author: huangqi
 */


#include "ns3/sshare-ipv4-helper.h"
#include "ns3/sshare-ipv4.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/names.h"

namespace ns3 {

SShareIpv4Helper::SShareIpv4Helper(Ipv4Address bootStrapIp, uint16_t bootStrapPort, Ipv4Address localIpAddress, uint16_t applicationPort, bool isIndex)
{
	this->m_factory.SetTypeId(SShareIpv4::GetTypeId());
	SetAttribute ("BootStrapIp", Ipv4AddressValue(bootStrapIp));
	SetAttribute ("BootStrapPort", UintegerValue(bootStrapPort));
	SetAttribute ("LocalIpAddress", Ipv4AddressValue(localIpAddress));
	SetAttribute ("ApplicationPort", UintegerValue(applicationPort));
	SetAttribute ("ChordEnable", BooleanValue(isIndex));
}

void
SShareIpv4Helper::SetAttribute(
		  std::string name,
		  const AttributeValue &value)
{
	m_factory.Set (name, value);
}

ApplicationContainer
SShareIpv4Helper::Install (Ptr<Node> node) const
{
	return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
SShareIpv4Helper::Install (std::string nodeName) const
{
	Ptr<Node> node = Names::Find<Node> (nodeName);
	return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
SShareIpv4Helper::Install (NodeContainer c) const
{
	ApplicationContainer apps;
	for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
		apps.Add (InstallPriv (*i));
    }
	return apps;
}

Ptr<Application>
SShareIpv4Helper::InstallPriv (Ptr<Node> node) const
{
	Ptr<Application> app = m_factory.Create<SShareIpv4> ();
	node->AddApplication (app);
	return app;
}

} //namespace ns3
