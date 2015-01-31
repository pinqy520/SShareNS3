

#include <fstream>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <string.h>
#include <vector>
#include <time.h>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/stats-module.h"
#include "ns3/random-variable.h"
#include "ns3/gnuplot.h"
#include "ns3/chord-ipv4-helper.h"
#include "ns3/chord-ipv4.h"
#include "ns3/sshare-ipv4-helper.h"
#include "ns3/sshare-ipv4.h"
#include "ns3/object.h"
#include "ns3/nstime.h"



using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SShareEx");

struct CommandHandlerArgument
{
	std::string scriptFile;
	NodeContainer nodeContainer;
	void *sshareEx;
};

UniformVariable random_var(0, 1);

class SShareEx
{
public:

	void Query(std::string s);

	std::vector<std::string> ImportSimulationData(std::string locationTablePath, std::string dataRecordPath, std::string sparqlPath);

	uint64_t GetARandomTime(uint64_t range);
	uint16_t GetARandomNumber(uint16_t range);

	void Start(std::string locationTablePath,
				std::string dataRecordPath,
				std::string sparqlPath,
				uint16_t indexNodesNum,
				uint16_t storageNodeNum,
				uint64_t simulationTime,
				uint16_t QueryNum,
				NodeContainer nodeContainer);
	void Stop();
	void Tokenize(const std::string& str,
					std::vector<std::string>& tokens,
					const std::string& delimiters);

	void InsertVNode(Ptr<ChordIpv4> chordApplication, std::string vNodeName);
	void VNodeAgain(std::string vNodeName);
	void InsertAgain(Ptr<DHashObject> insertobject);

    // Call backs by Chord Layer
    void JoinSuccess (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    void LookupSuccess (uint8_t* lookupKey, uint8_t lookupKeyBytes, Ipv4Address ipAddress, uint16_t port);
    void LookupFailure (uint8_t* lookupKey, uint8_t lookupKeyBytes);
    void InsertSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void RetrieveSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void InsertFailure (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes);
    void RetrieveFailure (uint8_t* key, uint8_t numBytes);
    void VNodeKeyOwnership (std::string vNodeName, uint8_t* key, uint8_t keyBytes, uint8_t* predecessorKey, uint8_t predecessorKeyBytes
			   ,uint8_t* oldPredecessorKey, uint8_t oldPredecessorKeyBytes, Ipv4Address predecessorIp, uint16_t predecessorPort);
    void GoOnProcessingSparql(std::string sparql);
    void PacketSendingRecord(uint32_t packetSize);
    void ProcessingCheck();


    //Statistics
    void TraceRing (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    void VNodeFailure (std::string vNodeName, uint8_t* key, uint8_t numBytes);
    static void* CommandHandler (void *arg);
    void ReadCommandTokens (void);
    void DrawGraph();

//	SShareEx* m_sshareEx;
	std::string m_SPARQLs;
	uint16_t m_sparqlnum;
	uint16_t m_indexNodesNum;
	uint16_t m_storageNodeNum;
	NodeContainer m_nodeContainer;
	uint64_t m_initTime;
	uint64_t m_waitTime;
	uint64_t m_traceTime;
	uint64_t m_simulationTime;
	std::vector<std::string> sparqlVec;
	uint16_t m_queryNum;
	uint64_t m_startexTime;
	uint32_t m_exRange;
	uint32_t m_insertCount;
	uint64_t m_stat_start_time;
	uint64_t m_stat_end_time;


	std::map<uint32_t, uint32_t> m_graphMap;

	std::vector<std::string> m_tokens;
	bool m_readyToRead;
	pthread_t commandHandlerThreadId;
    //Print
    void PrintCharArray (uint8_t*, uint32_t, std::ostream&);
    void PrintHexArray (uint8_t*, uint32_t, std::ostream&);

};

void SShareEx::Start(std::string locationTablePath,
						std::string dataRecordPath,
						std::string sparqlPath,
						uint16_t indexNodesNum,
						uint16_t storageNodeNum,
						uint64_t simulationTime,
						uint16_t QueryNum,
						NodeContainer nodeContainer)
{
	NS_LOG_FUNCTION_NOARGS();
	std::srand((int)time(NULL));
	if(locationTablePath[locationTablePath.size()-1] != '/')
		locationTablePath += '/';
	if(dataRecordPath[dataRecordPath.size()-1] != '/')
		dataRecordPath += '/';
	m_simulationTime = simulationTime;
	m_indexNodesNum = indexNodesNum;
	m_storageNodeNum = storageNodeNum;
	m_nodeContainer = nodeContainer;
	m_waitTime = 6000;
	m_initTime = 30000;
	m_queryNum = QueryNum;
	m_traceTime = m_indexNodesNum*100;
	sparqlVec = ImportSimulationData(locationTablePath,dataRecordPath,sparqlPath);
	m_readyToRead = false;
	m_insertCount = 0;
	m_exRange = 0;
	m_startexTime = 0;

	Simulator::Schedule (MilliSeconds (100), &SShareEx::ReadCommandTokens, this);
	if (pthread_create (&commandHandlerThreadId, NULL, SShareEx::CommandHandler, this) != 0)
	{
		perror ("New Thread Creation Failed, Exiting...");
		exit (1);
	}
}

void*
SShareEx::CommandHandler (void *arg)
{
	//struct CommandHandlerArgument th_argument = *((struct CommandHandlerArgument *) arg);
	//std::string scriptFile = th_argument.scriptFile;
	//NodeContainer nodeContainer = th_argument.nodeContainer;
	SShareEx* sshareEx = (SShareEx*)arg;

	//sshareEx -> m_sshareEx = sshareEx;
	//sshareEx -> m_nodeContainer = nodeContainer;
	//sshareEx -> m_scriptFile = scriptFile;

	while (1)
	{
		std::string commandLine;
		//read command from keyboard
		std::cout << "\nCommand > ";
		std::getline(std::cin, commandLine, '\n');
	    if (sshareEx->m_readyToRead == true)
	    {
	      std::cout << "Simulator busy, please try again..\n";
	      continue;
	    }

	    //std::vector<std::string> tokens;
		sshareEx->Tokenize (commandLine, sshareEx->m_tokens, " ");

		std::vector<std::string>::iterator iterator = sshareEx->m_tokens.begin();

		if (sshareEx->m_tokens.size() == 0)
		{
			continue;
		}
		//check for quit
		else if (*iterator == "quit")
		{
			break;
		}
		sshareEx -> m_readyToRead = true;
		//SINGLE THREADED SIMULATOR WILL CRASH, so let simulator schedule processcommandtokens!
		//sshareEx->ProcessCommandTokens (tokens, MilliSeconds (0.));

	}
	Simulator::Stop ();
	pthread_exit (NULL);
}

void
SShareEx::ReadCommandTokens (void)
{
  if (m_readyToRead == true)
  {

    if (m_tokens.size() > 0)
    {
    	if (m_tokens[0] == "trace" && m_tokens.size() == 2)
    	{
    		std::stringstream numstream(m_tokens[1]);
    		int number;
    		numstream >> number;
    		if(number >= this->m_indexNodesNum)
    			std::cout << "out of range" << std::endl;
    		else{
				Ptr<SShareIpv4> sshareApplication = m_nodeContainer.Get(number)->GetApplication(0)->GetObject<SShareIpv4> ();
				Ptr<ChordIpv4> chordApplication = m_nodeContainer.Get(number)->GetApplication(1)->GetObject<ChordIpv4> ();
				chordApplication->FireTraceRing(sshareApplication->GetLocalIp());
    		}
    	}
    	else if(m_tokens[0] == "join"){
    		VNodeAgain(m_tokens[1]);

    	}else if(m_tokens[0] == "import")
    	{
    		for(uint16_t i = 0; i < m_indexNodesNum; i++){
    			Ptr<SShareIpv4> sshareApplication = m_nodeContainer.Get(i)->GetApplication(0)->GetObject<SShareIpv4> ();
    			sshareApplication->SetStore();
    		}
    	}else if(m_tokens[0] == "startex"){
    		m_startexTime = Simulator::Now ().GetMilliSeconds();
    		for(uint16_t i = 0; i < m_queryNum; i++)
    		{
    			Simulator::Schedule (MilliSeconds(GetARandomTime(m_simulationTime)), &SShareEx::Query, this, sparqlVec[GetARandomNumber(sparqlVec.size())]);
    		}
    	}else if(m_tokens[0] == "clean"){
    		uint16_t nodenum = m_indexNodesNum + m_storageNodeNum;
    		for(uint16_t i = 0; i < nodenum; i++){
    			m_nodeContainer.Get(i)->GetApplication(0)->GetObject<SShareIpv4>()->m_eventTable.Clean();
    		}
    		std::cout<<"clean done!"<<std::endl;
    	}else if (m_tokens[0] == "query"){
    		if(m_tokens.size() == 3)
    		{
				std::stringstream node_num_stream(m_tokens[1]);
	    		int node_num;
	    		node_num_stream >> node_num;
	    		std::stringstream query_num_stream(m_tokens[2]);
	    		int query_num;
	    		query_num_stream >> query_num;
	    		m_stat_start_time = Simulator::Now ().GetMilliSeconds();
	    		m_nodeContainer.Get( node_num % (m_indexNodesNum + m_storageNodeNum) )->GetApplication(0)->GetObject<SShareIpv4> ()->Query(sparqlVec[query_num % sparqlVec.size()]);
    		}
    	}
    	else if (m_tokens[0] == "stat") {
    		std::cout << "Processing Time: " << this->m_stat_end_time - m_stat_start_time << " (ms)" << std::endl;
    		std::cout << "Data Transmission: "  << std::endl;
    		std::cout << "T" << "\t" << "D" << std::endl;

			uint32_t x;
			uint32_t y;
			uint32_t sta = m_stat_start_time/100;
			uint32_t ra = m_stat_end_time/100;
			uint32_t trans_count = 0;
    		for (x = sta - 1; x < ra; x++)
			{
				std::map<uint32_t, uint32_t>::iterator graphMapiter= this->m_graphMap.find(x);
				if(graphMapiter == m_graphMap.end())
				{
					y = 0;
				}else
				{
					y = (*graphMapiter).second;
				}
				trans_count += y;
				std::cout << x * 100 << "\t" << y << std::endl;
			}
			std::cout << "Count:" << "\t" << trans_count << std::endl;
    	}
    	else if(m_tokens[0] == "done"){
    		std::cout << "insert count: " << this->m_insertCount << std::endl;
    	}
    }
    m_tokens.clear();
    m_readyToRead = false;
  }
  Simulator::Schedule (MilliSeconds (100), &SShareEx::ReadCommandTokens, this);

}

void
SShareEx::InsertVNode(Ptr<ChordIpv4> chordApplication, std::string vNodeName)
{
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  NS_LOG_FUNCTION_NOARGS();
  unsigned char* md = (unsigned char*) malloc (20);
  const unsigned char* message = (const unsigned char*) vNodeName.c_str();
  ZEN_LIB::sha1 (message , vNodeName.length() , md);

  NS_LOG_INFO ("Scheduling Command InsertVNode...");
  chordApplication->InsertVNode(vNodeName, md, 20);
  free (md);
}

void
SShareEx::Stop ()
{
	NS_LOG_FUNCTION_NOARGS();
	  //Cancel keyboard thread
	pthread_cancel (commandHandlerThreadId);
	//Join keyboard thread
	pthread_join (commandHandlerThreadId, NULL);

}

void
SShareEx::Query(std::string s)
{
	NS_LOG_FUNCTION_NOARGS();

	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "SPARQL String:" << std::endl;
	std::cout << s;

	m_nodeContainer.Get(this->GetARandomNumber(m_indexNodesNum + m_storageNodeNum))->GetApplication(0)->GetObject<SShareIpv4> ()->Query(s);
}

uint64_t
SShareEx::GetARandomTime(uint64_t range)
{
	return random_var.GetInteger(0, range-1);
}

uint16_t
SShareEx::GetARandomNumber(uint16_t range)
{
	return random_var.GetInteger(0, range-1);
}

std::vector<std::string>
SShareEx::ImportSimulationData(std::string locationTablePath, std::string dataRecordPath, std::string sparqlPath)
{
	std::ifstream locationTableFile;
	std::ifstream dataRecordFile;
	std::string filepath;
	for(uint16_t i = 0; i < m_indexNodesNum; i++)
	{
		Ptr<SShareIpv4> sshareApplication = m_nodeContainer.Get(i)->GetApplication(0)->GetObject<SShareIpv4> ();
		Ptr<ChordIpv4> chordApplication = m_nodeContainer.Get(i)->GetApplication(1)->GetObject<ChordIpv4> ();
		Simulator::Schedule (MilliSeconds(m_waitTime+100*(i+1)), &SShareEx::InsertVNode, this, chordApplication, sshareApplication->GetLocalIp());
		//Get Location Data
		filepath = locationTablePath + sshareApplication->GetLocalIp() + ".lt";
		locationTableFile.open(filepath.c_str());
		if (locationTableFile.is_open())
		{
			NS_LOG_INFO ("Reading Location Table File: " << filepath);
			std::string oneItem;
			while (!locationTableFile.eof())
			{
				std::getline (locationTableFile, oneItem, '\n');
				if(oneItem != "")
				{
					std::vector<std::string> lt_tokens;
					Tokenize(oneItem, lt_tokens, "\t");
					if(lt_tokens.size() == 0)
					{
						NS_LOG_INFO ("Failed to LT_Tokenize" << filepath << "\n" << oneItem);
						continue;
					}

					//std::istringstream ipString(lt_tokens[1]);
					std::istringstream seqString(lt_tokens[2]);
					uint32_t ipaddr = Ipv4Address(lt_tokens[1].c_str()).Get();
					uint32_t seq;
					seqString >> seq;
					sshareApplication->AddLocationTable(lt_tokens[0], seq, ipaddr);
					//std::cout << lt_tokens[0] << '\t' << ipaddr << '\t' << seq << std::endl;
				}
			}
			locationTableFile.close();
		}
		//Get Record
		filepath = dataRecordPath + sshareApplication->GetLocalIp() + ".drt";
		dataRecordFile.open(filepath.c_str());
		if (dataRecordFile.is_open())
		{
			NS_LOG_INFO ("Reading Record Data File: " << filepath);
			std::string oneItem;
			while (!dataRecordFile.eof())
			{
				std::getline (dataRecordFile, oneItem, '\n');
				if(oneItem != "")
				{
					std::vector<std::string> rd_tokens;
					Tokenize(oneItem, rd_tokens, "\t");
					if(rd_tokens.size() == 0)
					{
						NS_LOG_INFO ("Failed to RD_Tokenize");
						continue;
					}
					std::istringstream dataSizeString(rd_tokens[1]);
					std::istringstream procTimeString(rd_tokens[2]);
					uint32_t dataSize;
					dataSizeString >> dataSize;
					uint64_t procTime;
					procTimeString >> procTime;

					//std::cout << "Importing Data: " << rd_tokens[0] << '\t' << dataSize << '\t' << procTime << std::endl;
					sshareApplication->AddDataRecord(rd_tokens[0], dataSize, procTime);
				}
			}
			dataRecordFile.close();
		}
		filepath = dataRecordPath + "common.drt";
		dataRecordFile.open(filepath.c_str());
		if (dataRecordFile.is_open())
		{
			NS_LOG_INFO ("Reading Record Data File: " << filepath);
			std::string oneItem;
			while (!dataRecordFile.eof())
			{
				std::getline (dataRecordFile, oneItem, '\n');
				if(oneItem != "")
				{
					std::vector<std::string> rd_tokens;
					Tokenize(oneItem, rd_tokens, "\t");
					if(rd_tokens.size() == 0)
					{
						NS_LOG_INFO ("Failed to RD_Tokenize");
						continue;
					}
					std::istringstream dataSizeString(rd_tokens[1]);
					std::istringstream procTimeString(rd_tokens[2]);
					uint32_t dataSize;
					dataSizeString >> dataSize;
					uint64_t procTime;
					procTimeString >> procTime;
					sshareApplication->AddDataRecord(rd_tokens[0], dataSize, procTime);
				}
			}
			dataRecordFile.close();
		}
	}
	for(uint16_t i = m_indexNodesNum; i < m_storageNodeNum + m_indexNodesNum; i++)
	{
		Ptr<SShareIpv4> sshareApplication = m_nodeContainer.Get(i)->GetApplication(0)->GetObject<SShareIpv4> ();
		//Get Record
		filepath = dataRecordPath + sshareApplication->GetLocalIp() + ".drt";
		dataRecordFile.open(filepath.c_str());
		if (dataRecordFile.is_open())
		{
			NS_LOG_INFO ("Reading Record Data File: " << filepath);
			std::string oneItem;
			while (!dataRecordFile.eof())
			{
				std::getline (dataRecordFile, oneItem, '\n');
				if(oneItem != "")
				{
					std::vector<std::string> rd_tokens;
					Tokenize(oneItem, rd_tokens, "\t");
					if(rd_tokens.size() == 0)
					{
						NS_LOG_INFO ("Failed to RD_Tokenize");
						continue;
					}
					std::istringstream dataSizeString(rd_tokens[1]);
					std::istringstream procTimeString(rd_tokens[2]);
					uint32_t dataSize;
					dataSizeString >> dataSize;
					uint64_t procTime;
					procTimeString >> procTime;
					sshareApplication->AddDataRecord(rd_tokens[0], dataSize, procTime);
				}
			}
			dataRecordFile.close();
		}
	}
	std::ifstream sparqlFile;
	sparqlFile.open(sparqlPath.c_str());
	std::vector<std::string> sparqls;
	if (sparqlFile.is_open())
	{
		std::string fileString = "";
		while(!sparqlFile.eof())
		{
			std::string tempstring;
			std::getline (sparqlFile, tempstring, '\n');
			fileString += tempstring + "\n";
		}
		Tokenize(fileString, sparqls, "==========");
		std::cout << "\n\n" << fileString << "\n\n";
		sparqlFile.close();
	}
	for(uint16_t z = 0; z < sparqls.size(); z++)
	{
		std::string::size_type startpos = sparqls[z].find_first_not_of('\n');
		std::string::size_type endpos = sparqls[z].find_last_not_of('\n');
		sparqls[z] = sparqls[z].substr(startpos, endpos-startpos+1);
		std::cout << "z = " << z << ":\n\n"<< sparqls[z] << "\n\n";
	}
	return sparqls;

}

void
SShareEx::JoinSuccess (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "VNode: " << vNodeName << " Joined successfully" << std::endl;
  PrintHexArray (key, numBytes, std::cout);
}

void
SShareEx::LookupSuccess (uint8_t* lookupKey, uint8_t lookupKeyBytes, Ipv4Address ipAddress, uint16_t port)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Lookup Success Ip: " << ipAddress << " Port: " << port << std::endl;
  PrintHexArray (lookupKey, lookupKeyBytes, std::cout);
}

void
SShareEx::LookupFailure (uint8_t* lookupKey, uint8_t lookupKeyBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Key Lookup failed" << std::endl;
  PrintHexArray (lookupKey, lookupKeyBytes, std::cout);
}

void
SShareEx::VNodeKeyOwnership (std::string vNodeName, uint8_t* key, uint8_t keyBytes, uint8_t* predecessorKey, uint8_t predecessorKeyBytes, uint8_t* oldPredecessorKey, uint8_t oldPredecessorKeyBytes, Ipv4Address predecessorIp, uint16_t predecessorPort)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "VNode: " << vNodeName << " Key Space Ownership change reported" << std::endl;
  std::cout << "New predecessor Ip: " << predecessorIp << " Port: " << predecessorPort << std::endl;
}


void
SShareEx::VNodeFailure (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  uint64_t thistime = Simulator::Now ().GetMilliSeconds();
  std::cout << "\nCurrent Simulation Time: " << thistime << std::endl;
  std::cout << "VNode: " << vNodeName << " Failed" << std::endl;
  if(int(thistime - this->m_traceTime) > int(this->m_indexNodesNum*100 + 500)){
	  this->m_traceTime = thistime;
  }
  VNodeAgain(vNodeName);
}

void
SShareEx::VNodeAgain(std::string vNodeName)
{
	std::string::size_type getpos = vNodeName.find_last_of('.');
	std::string num = vNodeName.substr(getpos+1, vNodeName.size()-getpos-1);
	int nodenum;
	std::stringstream numstream;
	numstream << num;
	numstream >> nodenum;
	nodenum = nodenum - 1;
	Ptr<ChordIpv4> tryagain_chordApplication = m_nodeContainer.Get(nodenum)->GetApplication(1)->GetObject<ChordIpv4> ();
//	InsertVNode(tryagain_chordApplication, vNodeName);
	Simulator::Schedule (MilliSeconds(555), &SShareEx::InsertVNode, this, tryagain_chordApplication, vNodeName);
}

void
SShareEx::InsertSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Insert Success!";
  PrintHexArray (key, numBytes, std::cout);
  uint32_t* sequenceResult = (uint32_t*)object;
  std::cout << "Ipv4 Addr: " << Ipv4Address(sequenceResult[0]) << std::endl;
  std::cout << "Frequency: " << sequenceResult[1] << std::endl;
  if(m_insertCount > 0)
  {
	  m_insertCount--;
  }
  //PrintCharArray (object, objectBytes, std::cout);
}

void
SShareEx::RetrieveSuccess (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{
	NS_LOG_FUNCTION_NOARGS();
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Retrieve Success!";
	PrintHexArray (key, numBytes, std::cout);
	uint32_t* sequenceResult = (uint32_t*)object;
  	std::cout << "Ipv4 Addr: " << Ipv4Address(sequenceResult[0]) << std::endl;
  	std::cout << "Frequency: " << sequenceResult[1] << std::endl;
}

void
SShareEx::InsertFailure (uint8_t* key, uint8_t numBytes, uint8_t* object, uint32_t objectBytes)
{
	NS_LOG_FUNCTION_NOARGS();
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << "Insert Failure Reported...";
	Ptr<DHashObject> insertobject = Create<DHashObject>(key, numBytes, object, objectBytes);
	Simulator::Schedule (MilliSeconds(m_insertCount), &SShareEx::InsertAgain, this, insertobject);
}

void
SShareEx::InsertAgain(Ptr<DHashObject> insertobject)
{
	NS_LOG_FUNCTION_NOARGS();
	uint32_t* sequenceResult = (uint32_t*)insertobject->GetObject();
	std::string ipstring;
	std::stringstream ipstream;
	ipstream << Ipv4Address(sequenceResult[0]);
	ipstream >> ipstring;
	std::string::size_type getpos = ipstring.find_last_of('.');
	std::string num = ipstring.substr(getpos+1, ipstring.size()-getpos-1);
	int nodenum;
	std::stringstream numstream;
	numstream << num;
	numstream >> nodenum;
	nodenum = nodenum - 1;
	m_insertCount++;
	Ptr<ChordIpv4> tryagain_chordApplication = m_nodeContainer.Get(nodenum)->GetApplication(1)->GetObject<ChordIpv4> ();
	tryagain_chordApplication->Insert(insertobject->GetObjectIdentifier()->GetKey(), insertobject->GetObjectIdentifier()->GetNumBytes(), insertobject->GetObject(), insertobject->GetSizeOfObject());
}

void
SShareEx::RetrieveFailure (uint8_t* key, uint8_t keyBytes)
{
  NS_LOG_FUNCTION_NOARGS();
  std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
  std::cout << "Retrieve Failure Reported...";
  PrintHexArray (key, keyBytes, std::cout);
}

void
SShareEx::GoOnProcessingSparql(std::string sparql)
{
	NS_LOG_FUNCTION_NOARGS();
	std::cout << "\nCurrent Simulation Time: " << Simulator::Now ().GetMilliSeconds() << std::endl;
	std::cout << sparql << std::endl;
}

void
SShareEx::PacketSendingRecord(uint32_t packetSize)
{
	uint64_t nowTime = Simulator::Now ().GetMilliSeconds();
	std::cout << "\nCurrent Simulation Time: " << nowTime << std::endl;
	NS_LOG_FUNCTION_NOARGS();
	m_stat_end_time = nowTime;
	nowTime = nowTime - this->m_startexTime;
	if(nowTime > this->m_exRange){
		m_exRange = nowTime + 100;
	}
	uint32_t insertNum = nowTime/100;
	std::map<uint32_t, uint32_t>::iterator graphMapiter= this->m_graphMap.find(insertNum);
	if(graphMapiter == m_graphMap.end())
	{
		m_graphMap.insert(std::make_pair(insertNum, packetSize));
	}else
	{
		(*graphMapiter).second += packetSize;
	}

}
void
SShareEx::ProcessingCheck(){
	uint64_t nowTime = Simulator::Now ().GetMilliSeconds();
	//std::cout << "\nCurrent Simulation Time: " << nowTime << std::endl;
	NS_LOG_FUNCTION_NOARGS();
	m_stat_end_time = nowTime;
}

void
SShareEx::DrawGraph()
{
	NS_LOG_FUNCTION_NOARGS();
	std::string fileNameWithNoExtension = "sshare-test";
	std::string graphicsFileName        = fileNameWithNoExtension + ".png";
	std::string plotFileName            = fileNameWithNoExtension + ".plt";
	std::string plotTitle               = "Network Load";
	std::string dataTitle               = "Network Traffic";

	// Instantiate the plot and set its title.
	Gnuplot plot (graphicsFileName);
	plot.SetTitle (plotTitle);

	// Make the graphics file, which the plot file will create when it
	// is used with Gnuplot, be a PNG file.
	plot.SetTerminal ("png");

	// Set the labels for each axis.
	plot.SetLegend ("Time", "Byte");

	// Set the range for the x axis.
	std::stringstream graphRangeStream("");
	graphRangeStream << "set xrange [0:+" << this->m_exRange << "]";
	std::string graphRange;
	graphRangeStream >> graphRange;
	plot.AppendExtra (graphRange);

	// Instantiate the dataset, set its title, and make the points be
	// plotted along with connecting lines.
	Gnuplot2dDataset dataset;
	dataset.SetTitle (dataTitle);
	dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);


	uint32_t x;
	uint32_t y;
	uint32_t r = m_exRange/100;

	// Create the 2-D dataset.
	for (x = 0; x < r; x++)
	{

		std::map<uint32_t, uint32_t>::iterator graphMapiter= this->m_graphMap.find(x);
		if(graphMapiter == m_graphMap.end())
		{
			y = 0;
		}else
		{
			y = (*graphMapiter).second;
		}

		dataset.Add ((double)(x*100), (double)y);
	}

	// Add the dataset to the plot.
	plot.AddDataset (dataset);

	// Open the plot file.
	std::ofstream plotFile (plotFileName.c_str());

	// Write the plot file.
	plot.GenerateOutput (plotFile);

	// Close the plot file.
	plotFile.close ();

}


void
SShareEx::TraceRing (std::string vNodeName, uint8_t* key, uint8_t numBytes)
{
  std::cout << "<" << vNodeName << ">" << std::endl;
  PrintHexArray (key, numBytes, std::cout);
}


void
SShareEx::Tokenize(const std::string& str,
					std::vector<std::string>& tokens,
					const std::string& delimiters)
{
	// Skip delimiters at beginning.
	std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
	// Find first "non-delimiter".
	std::string::size_type pos = str.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos)
	{
		// Found a token, add it to the vector.
		tokens.push_back(str.substr(lastPos, pos - lastPos));
		// Skip delimiters.  Note the "not_of"
		lastPos = str.find_first_not_of(delimiters, pos);
		// Find next "non-delimiter"
		pos = str.find_first_of(delimiters, lastPos);
	}
}

void
SShareEx::PrintCharArray (uint8_t* array, uint32_t size, std::ostream &os)
{
  os << "Char Array: ";
  for (uint32_t i = 0; i<size; i++)
    os << array[i];
  os << "\n";
}

void
SShareEx::PrintHexArray (uint8_t* array, uint32_t size, std::ostream &os)
{
  os << "Bytes: " << (uint16_t) size << "\n";
  os << "Array: \n";
  os << "[ ";
  for (uint8_t j=0;j<size;j++)
  {
    os << std::hex << "0x" <<(uint16_t) array[j] << " ";
  }
  os << std::dec << "]\n";
}

int main(int argc, char *argv[])
{
	uint16_t indexNodesNum = 0;
	uint16_t storageNodeNum = 0;
	std::cout << "index nodes: " << std::endl;
	std::cin >> indexNodesNum;
	std::cout << "storage nodes: " << std::endl;
	std::cin >> storageNodeNum;
	if(indexNodesNum == 0 || storageNodeNum == 0){
		return 0;
	}
	std::cout << "=============== Start ============= " << std::endl;
	std::cout << "index nodes: ";
	std::cout << indexNodesNum << std::endl;
	std::cout << "storage nodes: ";
	std::cout << storageNodeNum << std::endl;
	uint64_t simulationTime = 5000;
	uint16_t QueryNum = 1;
	std::string locationTablePath = "/home/huangqi/ex/export/";
	std::string dataRecordPath = "/home/huangqi/ex/export/";
	std::string sparqlPath = "/home/huangqi/ex/sparql.query";
	std::cout << "processing information path: " << std::endl;
	std::cout << "default(/home/huangqi/ex/export/)" << std::endl;
	std::string pit_path = "";
	std::cin >> pit_path;
	if(pit_path != ""){
		locationTablePath = pit_path;
		dataRecordPath = pit_path;
	}
	std::cout << "set:" << locationTablePath << std::endl;
	std::cout << "---------------------------" << std::endl;
	std::cout << "query file path: " << std::endl;
	std::cout << "default(/home/huangqi/ex/sparql.query)" << std::endl;
	std::string q_path = "";
	std::cin >> q_path;
	if(q_path != ""){
		sparqlPath = q_path;
	}
	std::cout << "set:" << q_path << std::endl;
	std::cout << "---------------------------" << std::endl;
	std::string chord_running_information = "n";
	std::cout << "show chord running information?(y/n):" << std::endl;
	std::cin >> chord_running_information;
	std::cout << "---------------------------" << std::endl;
	//
	// Allow the user to override any of the defaults and the above Bind() at
	// run-time, via command-line arguments
	//

	CommandLine cmd;
	cmd.AddValue ("IndexNodes", "The number of index nodes.", indexNodesNum);
	cmd.AddValue ("StorageNodes", "The number of storage nodes.", storageNodeNum);
	cmd.AddValue ("Time", "How long the simulation runs(ms).", simulationTime);
	cmd.AddValue ("QueriesNum", "The number of queries that will be processed.", QueryNum);
	cmd.AddValue ("LocationTable", "The path of location table file.", locationTablePath);
	cmd.AddValue ("DataRecord", "The path of data record file.", dataRecordPath);
	cmd.AddValue ("SparqlFolder", "SPARQL query library path.", sparqlPath);
	cmd.Parse (argc, argv);


	std::cout << "Number of index nodes to simulate: " << (uint16_t) indexNodesNum << "\n";
	std::cout << "Number of storage nodes to simulate: " << (uint16_t) storageNodeNum << "\n";

	LogComponentEnable("SShareEx", LOG_LEVEL_ALL);
	if(chord_running_information == "y"){
		LogComponentEnable("ChordIpv4Application", LOG_LEVEL_ALL);
	}else{
		LogComponentEnable("ChordIpv4Application", LOG_LEVEL_ERROR);
	}
	LogComponentEnable("ChordIdentifier", LOG_LEVEL_ERROR);
	LogComponentEnable("ChordTransaction", LOG_LEVEL_ERROR);
	LogComponentEnable("ChordVNode", LOG_LEVEL_ERROR);
	LogComponentEnable("ChordNodeTable", LOG_LEVEL_ERROR);

	LogComponentEnable("DHashIpv4", LOG_LEVEL_ERROR);
	LogComponentEnable("DHashConnection", LOG_LEVEL_ERROR);

	LogComponentEnable("SShareIpv4Application", LOG_LEVEL_ERROR);
	LogComponentEnable("SShareEventTable", LOG_LEVEL_ERROR);
	LogComponentEnable("SShareConnection", LOG_LEVEL_ERROR);


	uint16_t nodesNum = indexNodesNum + storageNodeNum;

	//------------------------------------------------------------
	//-- Create nodes and network stacks
	//--------------------------------------------
	NS_LOG_INFO ("Creating nodes.");
	NodeContainer nodes;
	nodes.Create (nodesNum);

	InternetStackHelper internet;
	internet.Install (nodes);

	NS_LOG_INFO ("Create channels.");

	CsmaHelper csma;
	csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
	csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
	csma.SetDeviceAttribute ("Mtu", UintegerValue (1400));
	NetDeviceContainer d = csma.Install (nodes);

	Ipv4AddressHelper ipv4;

	NS_LOG_INFO ("Assign IP Addresses.");
	ipv4.SetBase ("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer ipContainer = ipv4.Assign (d);

	NS_LOG_INFO ("Create Applications.");



	SShareEx sshareEx;


	uint16_t chordPort = 2000;
	uint16_t ssharePort = 10000;
	for (int j=0; j<indexNodesNum; j++)
	{
		SShareIpv4Helper sshareHelper(ipContainer.GetAddress(sshareEx.GetARandomNumber(indexNodesNum)), ssharePort, ipContainer.GetAddress(j), ssharePort, true);
		ApplicationContainer sshareApps = sshareHelper.Install (nodes.Get(j));
		sshareApps.Start(Seconds (0.0));
		Ptr<SShareIpv4> sshareApplication = nodes.Get(j)->GetApplication(0)->GetObject<SShareIpv4> ();
		std::cout << sshareApplication->GetLocalIp() << std::endl;


		ChordIpv4Helper chordHelper(ipContainer.GetAddress(0), chordPort, ipContainer.GetAddress(j), chordPort, chordPort+1, chordPort+2);
		ApplicationContainer chordApps = chordHelper.Install (nodes.Get(j));
		chordApps.Start(Seconds (0.0));
		Ptr<ChordIpv4> chordApplication = nodes.Get(j)->GetApplication(1)->GetObject<ChordIpv4> ();
		chordApplication->SetJoinSuccessCallback (MakeCallback(&SShareEx::JoinSuccess, &sshareEx));
		chordApplication->SetLookupSuccessCallback (MakeCallback(&SShareEx::LookupSuccess, &sshareEx));
		chordApplication->SetLookupFailureCallback (MakeCallback(&SShareEx::LookupFailure, &sshareEx));
		chordApplication->SetTraceRingCallback (MakeCallback(&SShareEx::TraceRing, &sshareEx));
		chordApplication->SetVNodeFailureCallback(MakeCallback(&SShareEx::VNodeFailure, &sshareEx));
		chordApplication->SetVNodeKeyOwnershipCallback(MakeCallback(&SShareEx::VNodeKeyOwnership, &sshareEx));
	     //DHash configuration:: Needs to be done once but can be overwritten...
		chordApplication->SetInsertSuccessCallback (MakeCallback(&SShareEx::InsertSuccess, &sshareEx));
		sshareApplication->SetSeqRetrieveSuccessCallback (MakeCallback(&SShareEx::RetrieveSuccess, &sshareEx));
		chordApplication->SetInsertFailureCallback (MakeCallback(&SShareEx::InsertFailure, &sshareEx));
		sshareApplication->SetSeqRetrieveFailureCallback (MakeCallback(&SShareEx::RetrieveFailure, &sshareEx));
		sshareApplication->SetGoOnProcessingSparqlCallback(MakeCallback(&SShareEx::GoOnProcessingSparql, &sshareEx));

		sshareApplication->SetPacketSendingCallback(MakeCallback(&SShareEx::PacketSendingRecord, &sshareEx));
		sshareApplication->SetProcessingCallback(MakeCallback(&SShareEx::ProcessingCheck, &sshareEx));

		sshareApplication->SetChordApplication(chordApplication);

	}

	for(int k=indexNodesNum; k<nodesNum; k++)
	{
		SShareIpv4Helper sshareHelper(ipContainer.GetAddress(sshareEx.GetARandomNumber(indexNodesNum)), ssharePort, ipContainer.GetAddress(k), ssharePort, false);
		ApplicationContainer sshareApps = sshareHelper.Install (nodes.Get(k));
		sshareApps.Start(Seconds (0.0));
		Ptr<SShareIpv4> sshareApplication = nodes.Get(k)->GetApplication(0)->GetObject<SShareIpv4> ();
		sshareApplication->SetPacketSendingCallback(MakeCallback(&SShareEx::PacketSendingRecord, &sshareEx));
		sshareApplication->SetProcessingCallback(MakeCallback(&SShareEx::ProcessingCheck, &sshareEx));
		std::cout << sshareApplication->GetLocalIp() << std::endl;
	}

	sshareEx.Start(locationTablePath,
					dataRecordPath,
					sparqlPath,
					indexNodesNum,
					storageNodeNum,
					simulationTime,
					QueryNum,
					nodes);

	//AsciiTraceHelper asciiHelper;
	//Ptr<OutputStreamWrapper> stream = asciiHelper.CreateFileStream("traceOut.txt");
	//csma.EnableAsciiAll(stream);

	NS_LOG_INFO ("Run Simulation.");
	Simulator::Run ();
	sshareEx.Stop ();

	//sshareEx.DrawGraph();
	Simulator::Destroy ();
	NS_LOG_INFO ("Done.");

	return 0;
}
