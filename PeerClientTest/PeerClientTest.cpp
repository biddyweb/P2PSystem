#include <QCoreApplication>
#include <iostream>
#include <QDebug>


#include "talk/base/dscp.h"
#include "talk/base/fakenetwork.h"
#include "talk/base/firewallsocketserver.h"
#include "talk/base/helpers.h"
#include "talk/base/logging.h"
#include "talk/base/natserver.h"
#include "talk/base/natsocketfactory.h"
#include "talk/base/physicalsocketserver.h"
#include "talk/base/proxyserver.h"
#include "talk/base/socketaddress.h"
#include "talk/base/thread.h"
#include "talk/base/virtualsocketserver.h"
#include "talk/p2p/base/p2ptransportchannel.h"
#include "talk/p2p/base/testrelayserver.h"
#include "talk/p2p/base/teststunserver.h"
#include "talk/p2p/client/basicportallocator.h"

#include "transporttest.h"


#include "talk/app/kaerp2p/kaer_session_client.h"
#include "talk/base/win32socketinit.h"
#include "talk/base/win32socketserver.h"

#include "myconductor.h"

#define WAIT_(ex, timeout, res) \
    do { \
    uint32 start = talk_base::Time(); \
    res = (ex); \
    while (!res && talk_base::Time() < start + timeout) { \
    talk_base::Thread::Current()->ProcessMessages(1); \
    res = (ex); \
    } \
    } while (0);

#define EXPECT_TRUE_WAIT_MARGIN(ex, timeout, margin) \
    do { \
    bool res; \
    WAIT_(ex, timeout, res); \
    if (res) { \
    break; \
    } \
    LOG(LS_WARNING) << "Expression " << #ex << " still not true after " << \
    timeout << "ms; waiting an additional " << margin << "ms"; \
    WAIT_(ex, margin, res); \
    if (!res) { \
    LOG(LS_WARNING)<<"asdfsdfsdf wait failed"; \
    return 0;\
    } \
    } while (0);



int main(int argc, char *argv[])
{
    //QCoreApplication a(argc, argv);

//    TransportTest * newTest = new TransportTest();

//    //cricket::TransportChannel * channel = newTest->CreateChannel(1);
//    newTest->SetupChannel();
//    newTest->Connect();

//    //std::cout<<channel->ToString()<<std::endl;
//    qDebug("start wait");


//    qDebug("end wait");

   // std::cout<<channel->ToString()<<std::endl;

    //return a.exec();

//    talk_base::scoped_ptr<kaerp2p::kaer_session_client> client(
//                new talk_base::RefCountedObject<kaerp2p::kaer_session_client>());

//    client->CreateTunnel("test");

    talk_base::EnsureWinsockInit();
    talk_base::Win32Thread w32_thread;
    talk_base::ThreadManager::Instance()->SetCurrentThread(&w32_thread);

    PeerConnectionClient client;
    talk_base::scoped_refptr<kaerp2p::MyConductor> conductor(
                   new talk_base::RefCountedObject<kaerp2p::MyConductor>(&client));

    std::string serverIp = "219.146.201.106";

    conductor->StartLogin(serverIp,8888);
    std::cout<<"connect end"<<std::endl;

   //     int res;
    //    WAIT_(false,30000,res);

    talk_base::Thread::Current()->Run();
    return 0;
}
