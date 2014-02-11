#ifndef TRANSPORTTEST_H
#define TRANSPORTTEST_H

#include "talk/base/refcount.h"
#include "talk/base/scoped_ptr.h"
#include "talk/base/scoped_ref_ptr.h"
#include "talk/base/socketaddress.h"
#include "talk/p2p/base/port.h"
#include "talk/p2p/base/transport.h"
#include "talk/base/thread.h"
#include "talk/p2p/base/p2ptransport.h"
#include "talk/p2p/client/basicportallocator.h"
#include "talk/base/socketaddress.h"
#include "talk/p2p/base/basicpacketsocketfactory.h"

using talk_base::SocketAddress;

static const SocketAddress kRealStun("stun.l.google.com",19302);
// The address of the public STUN server.
static const SocketAddress kStunAddr("99.99.99.1", 3478);
// The addresses for the public relay server.
static const SocketAddress kRelayUdpIntAddr("99.99.99.2", 5000);
static const SocketAddress kRelayUdpExtAddr("99.99.99.3", 5001);
static const SocketAddress kRelayTcpIntAddr("99.99.99.2", 5002);
static const SocketAddress kRelayTcpExtAddr("99.99.99.3", 5003);
static const SocketAddress kRelaySslTcpIntAddr("99.99.99.2", 5004);
static const SocketAddress kRelaySslTcpExtAddr("99.99.99.3", 5005);
static const SocketAddress kAnyAddr(talk_base::IPAddress(INADDR_ANY), 0);

class TransportTest:public sigslot::has_slots<>
{
public:
    TransportTest()
        :thread_(talk_base::Thread::Current()),

          allocator_(new cricket::BasicPortAllocator(
                         &network_manager_, kRealStun, kAnyAddr,
                         kAnyAddr, kAnyAddr)),
          transport_(new cricket::P2PTransport(
                         thread_, thread_, "testTransport", allocator_.get()))
    {
        transport_->SignalConnecting.connect(this, &TransportTest::OnConnecting);
        transport_->SignalCandidatesReady.connect(
                    this, &TransportTest::OnTransportCandidatesReady);
        transport_->SignalRequestSignaling.connect(
                    this,&TransportTest::OnTransportSignalingReady);
    }
    ~TransportTest(){
        transport_->DestroyAllChannels();
    }
    bool SetupChannel() {

        channel_ = CreateChannel(1);
        return (channel_ != NULL);
    }
    void Connect(){
        transport_->ConnectChannels();
    }

    cricket::TransportChannelImpl* CreateChannel(int component){

        return transport_->CreateChannel(component);
    }

    void OnTransportCandidatesReady(cricket::Transport* transport,
                                    const cricket::Candidates& candidates) {
        ASSERT(transport == transport_.get());
        for (cricket::Candidates::const_iterator cand = candidates.begin();
             cand != candidates.end(); ++cand) {
            LOG(INFO)<<"OnTransportCandidatesReady::candidate infos:    "<<cand->ToString();
        }
        //SignalCandidatesReady(this, candidates);
    }
    void OnTransportSignalingReady(cricket::Transport* transport){
        LOG(INFO)<<"OnTransportSignalingReady";
        ASSERT(transport == transport_.get());
        transport->OnSignalingReady();
    }

public:
    void OnConnecting(cricket::Transport* transport) {
        LOG(INFO)<<"Onconnecting";
        connecting_signalled_ = true;
    }

    talk_base::Thread* thread_;
    talk_base::BasicNetworkManager network_manager_;
    talk_base::scoped_ptr<cricket::PortAllocator> allocator_;
    talk_base::BasicPacketSocketFactory socket_factory_;
    talk_base::scoped_ptr<cricket::P2PTransport> transport_;
    bool connecting_signalled_;
    cricket::TransportChannelImpl* channel_;

};

#endif // TRANSPORTTEST_H
