#ifndef CHANNELTEST_H
#define CHANNELTEST_H

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

using cricket::kDefaultPortAllocatorFlags;
using cricket::kMinimumStepDelay;
using cricket::kDefaultStepDelay;
using cricket::PORTALLOCATOR_ENABLE_SHARED_UFRAG;
using cricket::PORTALLOCATOR_ENABLE_SHARED_SOCKET;
using talk_base::SocketAddress;

static const int kDefaultTimeout = 1000;

// Addresses on the public internet.
static const SocketAddress kPublicAddrs[2] =
{ SocketAddress("11.11.11.11", 0), SocketAddress("22.22.22.22", 0) };
// IPv6 Addresses on the public internet.
static const SocketAddress kIPv6PublicAddrs[2] = {
    SocketAddress("2400:4030:1:2c00:be30:abcd:efab:cdef", 0),
    SocketAddress("2620:0:1000:1b03:2e41:38ff:fea6:f2a4", 0)
};
// For configuring multihomed clients.
static const SocketAddress kAlternateAddrs[2] =
{ SocketAddress("11.11.11.101", 0), SocketAddress("22.22.22.202", 0) };
// Addresses for HTTP proxy servers.
static const SocketAddress kHttpsProxyAddrs[2] =
{ SocketAddress("11.11.11.1", 443), SocketAddress("22.22.22.1", 443) };
// Addresses for SOCKS proxy servers.
static const SocketAddress kSocksProxyAddrs[2] =
{ SocketAddress("11.11.11.1", 1080), SocketAddress("22.22.22.1", 1080) };
// Internal addresses for NAT boxes.
static const SocketAddress kNatAddrs[2] =
{ SocketAddress("192.168.1.1", 0), SocketAddress("192.168.2.1", 0) };
// Private addresses inside the NAT private networks.
static const SocketAddress kPrivateAddrs[2] =
{ SocketAddress("192.168.1.11", 0), SocketAddress("192.168.2.22", 0) };
// For cascaded NATs, the internal addresses of the inner NAT boxes.
static const SocketAddress kCascadedNatAddrs[2] =
{ SocketAddress("192.168.10.1", 0), SocketAddress("192.168.20.1", 0) };
// For cascaded NATs, private addresses inside the inner private networks.
static const SocketAddress kCascadedPrivateAddrs[2] =
{ SocketAddress("192.168.10.11", 0), SocketAddress("192.168.20.22", 0) };
// The address of the public STUN server.
static const SocketAddress kStunAddr("99.99.99.1", cricket::STUN_SERVER_PORT);
// The addresses for the public relay server.
static const SocketAddress kRelayUdpIntAddr("99.99.99.2", 5000);
static const SocketAddress kRelayUdpExtAddr("99.99.99.3", 5001);
static const SocketAddress kRelayTcpIntAddr("99.99.99.2", 5002);
static const SocketAddress kRelayTcpExtAddr("99.99.99.3", 5003);
static const SocketAddress kRelaySslTcpIntAddr("99.99.99.2", 5004);
static const SocketAddress kRelaySslTcpExtAddr("99.99.99.3", 5005);
// Based on ICE_UFRAG_LENGTH
static const char* kIceUfrag[4] = {"TESTICEUFRAG0000", "TESTICEUFRAG0001",
                                   "TESTICEUFRAG0002", "TESTICEUFRAG0003"};
// Based on ICE_PWD_LENGTH
static const char* kIcePwd[4] = {"TESTICEPWD00000000000000",
                                 "TESTICEPWD00000000000001",
                                 "TESTICEPWD00000000000002",
                                 "TESTICEPWD00000000000003"};

struct ChannelData {
    bool CheckData(const char* data, int len) {
        bool ret = false;
        if (!ch_packets_.empty()) {
            std::string packet =  ch_packets_.front();
            ret = (packet == std::string(data, len));
            ch_packets_.pop_front();
        }
        return ret;
    }

    std::string name_;  // TODO - Currently not used.
    std::list<std::string> ch_packets_;
    talk_base::scoped_ptr<cricket::P2PTransportChannel> ch_;
};

struct Endpoint {
    Endpoint() : signaling_delay_(0), role_(cricket::ICEROLE_UNKNOWN),
        tiebreaker_(0), role_conflict_(false),
        protocol_type_(cricket::ICEPROTO_GOOGLE) {}
    bool HasChannel(cricket::TransportChannel* ch) {
        return (ch == cd1_.ch_.get() || ch == cd2_.ch_.get());
    }
    ChannelData* GetChannelData(cricket::TransportChannel* ch) {
        if (!HasChannel(ch)) return NULL;
        if (cd1_.ch_.get() == ch)
            return &cd1_;
        else
            return &cd2_;
    }
    void SetSignalingDelay(int delay) { signaling_delay_ = delay; }

    void SetIceRole(cricket::IceRole role) { role_ = role; }
    cricket::IceRole ice_role() { return role_; }
    void SetIceProtocolType(cricket::IceProtocolType type) {
        protocol_type_ = type;
    }
    cricket::IceProtocolType protocol_type() { return protocol_type_; }
    void SetIceTiebreaker(uint64 tiebreaker) { tiebreaker_ = tiebreaker; }
    uint64 GetIceTiebreaker() { return tiebreaker_; }
    void OnRoleConflict(bool role_conflict) { role_conflict_ = role_conflict; }
    bool role_conflict() { return role_conflict_; }
    void SetAllocationStepDelay(uint32 delay) {
        allocator_->set_step_delay(delay);
    }
    void SetAllowTcpListen(bool allow_tcp_listen) {
        allocator_->set_allow_tcp_listen(allow_tcp_listen);
    }

    talk_base::FakeNetworkManager network_manager_;
    talk_base::scoped_ptr<cricket::PortAllocator> allocator_;
    ChannelData cd1_;
    ChannelData cd2_;
    int signaling_delay_;
    cricket::IceRole role_;
    uint64 tiebreaker_;
    bool role_conflict_;
    cricket::IceProtocolType protocol_type_;
};

class P2PTransportChannelTestBase : public talk_base::MessageHandler,
        public sigslot::has_slots<> {
public:
    P2PTransportChannelTestBase()
        : main_(talk_base::Thread::Current()),
          pss_(new talk_base::PhysicalSocketServer),
          vss_(new talk_base::VirtualSocketServer(pss_.get())),
          nss_(new talk_base::NATSocketServer(vss_.get())),
          ss_(new talk_base::FirewallSocketServer(nss_.get())),
          ss_scope_(ss_.get()),
          stun_server_(main_, kStunAddr),
          relay_server_(main_, kRelayUdpIntAddr, kRelayUdpExtAddr,
                        kRelayTcpIntAddr, kRelayTcpExtAddr,
                        kRelaySslTcpIntAddr, kRelaySslTcpExtAddr),
          socks_server1_(ss_.get(), kSocksProxyAddrs[0],
          ss_.get(), kSocksProxyAddrs[0]),
          socks_server2_(ss_.get(), kSocksProxyAddrs[1],
          ss_.get(), kSocksProxyAddrs[1]),
          clear_remote_candidates_ufrag_pwd_(false) {
        ep1_.role_ = cricket::ICEROLE_CONTROLLING;
        ep2_.role_ = cricket::ICEROLE_CONTROLLED;
        ep1_.allocator_.reset(new cricket::BasicPortAllocator(
                                  &ep1_.network_manager_, kStunAddr, kRelayUdpIntAddr,
                                  kRelayTcpIntAddr, kRelaySslTcpIntAddr));
        ep2_.allocator_.reset(new cricket::BasicPortAllocator(
                                  &ep2_.network_manager_, kStunAddr, kRelayUdpIntAddr,
                                  kRelayTcpIntAddr, kRelaySslTcpIntAddr));
    }

public:
    enum Config {
        OPEN,                           // Open to the Internet
        NAT_FULL_CONE,                  // NAT, no filtering
        NAT_ADDR_RESTRICTED,            // NAT, must send to an addr to recv
        NAT_PORT_RESTRICTED,            // NAT, must send to an addr+port to recv
        NAT_SYMMETRIC,                  // NAT, endpoint-dependent bindings
        NAT_DOUBLE_CONE,                // Double NAT, both cone
        NAT_SYMMETRIC_THEN_CONE,        // Double NAT, symmetric outer, cone inner
        BLOCK_UDP,                      // Firewall, UDP in/out blocked
        BLOCK_UDP_AND_INCOMING_TCP,     // Firewall, UDP in/out and TCP in blocked
        BLOCK_ALL_BUT_OUTGOING_HTTP,    // Firewall, only TCP out on 80/443
        PROXY_HTTPS,                    // All traffic through HTTPS proxy
        PROXY_SOCKS,                    // All traffic through SOCKS proxy
        NUM_CONFIGS
    };

    struct Result {
        Result(const std::string& lt, const std::string& lp,
               const std::string& rt, const std::string& rp,
               const std::string& lt2, const std::string& lp2,
               const std::string& rt2, const std::string& rp2, int wait)
            : local_type(lt), local_proto(lp), remote_type(rt), remote_proto(rp),
              local_type2(lt2), local_proto2(lp2), remote_type2(rt2),
              remote_proto2(rp2), connect_wait(wait) {
        }
        std::string local_type;
        std::string local_proto;
        std::string remote_type;
        std::string remote_proto;
        std::string local_type2;
        std::string local_proto2;
        std::string remote_type2;
        std::string remote_proto2;
        int connect_wait;
    };


    struct CandidateData : public talk_base::MessageData {
        CandidateData(cricket::TransportChannel* ch, const cricket::Candidate& c)
            : channel(ch), candidate(c) {
        }
        cricket::TransportChannel* channel;
        cricket::Candidate candidate;
    };

    ChannelData* GetChannelData(cricket::TransportChannel* channel) {
        if (ep1_.HasChannel(channel))
            return ep1_.GetChannelData(channel);
        else
            return ep2_.GetChannelData(channel);
    }

    void CreateChannels(int num) {
        std::string ice_ufrag_ep1_cd1_ch = kIceUfrag[0];
        std::string ice_pwd_ep1_cd1_ch = kIcePwd[0];
        std::string ice_ufrag_ep2_cd1_ch = kIceUfrag[1];
        std::string ice_pwd_ep2_cd1_ch = kIcePwd[1];
        ep1_.cd1_.ch_.reset(CreateChannel(
                                0, cricket::ICE_CANDIDATE_COMPONENT_DEFAULT,
                                ice_ufrag_ep1_cd1_ch, ice_pwd_ep1_cd1_ch,
                                ice_ufrag_ep2_cd1_ch, ice_pwd_ep2_cd1_ch));
        ep2_.cd1_.ch_.reset(CreateChannel(
                                1, cricket::ICE_CANDIDATE_COMPONENT_DEFAULT,
                                ice_ufrag_ep2_cd1_ch, ice_pwd_ep2_cd1_ch,
                                ice_ufrag_ep1_cd1_ch, ice_pwd_ep1_cd1_ch));
        if (num == 2) {
            std::string ice_ufrag_ep1_cd2_ch = kIceUfrag[2];
            std::string ice_pwd_ep1_cd2_ch = kIcePwd[2];
            std::string ice_ufrag_ep2_cd2_ch = kIceUfrag[3];
            std::string ice_pwd_ep2_cd2_ch = kIcePwd[3];
            // In BUNDLE each endpoint must share common ICE credentials.
            if (ep1_.allocator_->flags() & cricket::PORTALLOCATOR_ENABLE_BUNDLE) {
                ice_ufrag_ep1_cd2_ch = ice_ufrag_ep1_cd1_ch;
                ice_pwd_ep1_cd2_ch = ice_pwd_ep1_cd1_ch;
            }
            if (ep2_.allocator_->flags() & cricket::PORTALLOCATOR_ENABLE_BUNDLE) {
                ice_ufrag_ep2_cd2_ch = ice_ufrag_ep2_cd1_ch;
                ice_pwd_ep2_cd2_ch = ice_pwd_ep2_cd1_ch;
            }
            ep1_.cd2_.ch_.reset(CreateChannel(
                                    0, cricket::ICE_CANDIDATE_COMPONENT_DEFAULT,
                                    ice_ufrag_ep1_cd2_ch, ice_pwd_ep1_cd2_ch,
                                    ice_ufrag_ep2_cd2_ch, ice_pwd_ep2_cd2_ch));
            ep2_.cd2_.ch_.reset(CreateChannel(
                                    1, cricket::ICE_CANDIDATE_COMPONENT_DEFAULT,
                                    ice_ufrag_ep2_cd2_ch, ice_pwd_ep2_cd2_ch,
                                    ice_ufrag_ep1_cd2_ch, ice_pwd_ep1_cd2_ch));
        }
    }
    cricket::P2PTransportChannel* CreateChannel(
            int endpoint,
            int component,
            const std::string& local_ice_ufrag,
            const std::string& local_ice_pwd,
            const std::string& remote_ice_ufrag,
            const std::string& remote_ice_pwd) {

        std::stringstream contentStream;
        contentStream<<"test content name "<< endpoint;
        std::string contentName = contentStream.str();
//        cricket::P2PTransportChannel* channel = new cricket::P2PTransportChannel(
//                    "test content name", component, NULL, GetAllocator(endpoint));
        cricket::P2PTransportChannel* channel = new cricket::P2PTransportChannel(
                    contentName, component, NULL, GetAllocator(endpoint));
        channel->SignalRequestSignaling.connect(
                    this, &P2PTransportChannelTestBase::OnChannelRequestSignaling);
        channel->SignalCandidateReady.connect(this,
                                              &P2PTransportChannelTestBase::OnCandidate);
        channel->SignalReadPacket.connect(
                    this, &P2PTransportChannelTestBase::OnReadPacket);
        channel->SignalRoleConflict.connect(
                    this, &P2PTransportChannelTestBase::OnRoleConflict);
        channel->SetIceProtocolType(GetEndpoint(endpoint)->protocol_type());
        channel->SetIceCredentials(local_ice_ufrag, local_ice_pwd);
        if (clear_remote_candidates_ufrag_pwd_) {
            // This only needs to be set if we're clearing them from the
            // candidates.  Some unit tests rely on this not being set.
            channel->SetRemoteIceCredentials(remote_ice_ufrag, remote_ice_pwd);
        }
        channel->SetIceRole(GetEndpoint(endpoint)->ice_role());
        channel->SetIceTiebreaker(GetEndpoint(endpoint)->GetIceTiebreaker());
        channel->Connect();
        return channel;
    }
    void DestroyChannels() {
        ep1_.cd1_.ch_.reset();
        ep2_.cd1_.ch_.reset();
        ep1_.cd2_.ch_.reset();
        ep2_.cd2_.ch_.reset();
    }


    void TestSendRecv(int channels) {
//        for (int i = 0; i < 10; ++i) {
//            const char* data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
//            int len = static_cast<int>(strlen(data));
//            int res;
//            bool b;
//            // local_channel1 <==> remote_channel1
//            WAIT_(this->SendData(ep1_ch1(), data, len),1000,res);
//            WAIT_(this->CheckDataOnChannel(ep2_ch1(), data, len),1000,b);
//            WAIT_(this->SendData(ep2_ch1(), data, len),1000,res);
//            WAIT_(this->CheckDataOnChannel(ep1_ch1(), data, len), 1000,b);

//            if (channels == 2 && ep1_ch2() && ep2_ch2()) {
//                // local_channel2 <==> remote_channel2
//                WAIT_(this->SendData(ep1_ch2(), data, len),1000,res);
//                WAIT_(this->CheckDataOnChannel(ep2_ch2(), data, len),1000,b);
//                WAIT_(this->SendData(ep2_ch2(), data, len),1000,res);
//                WAIT_(this->CheckDataOnChannel(ep1_ch2(), data, len), 1000,b);

//                //        EXPECT_EQ_WAIT(len, SendData(ep1_ch2(), data, len), 1000);
//                //        EXPECT_TRUE_WAIT(CheckDataOnChannel(ep2_ch2(), data, len), 1000);
//                //        EXPECT_EQ_WAIT(len, SendData(ep2_ch2(), data, len), 1000);
//                //        EXPECT_TRUE_WAIT(CheckDataOnChannel(ep1_ch2(), data, len), 1000);
//            }
//        }
    }

    cricket::P2PTransportChannel* ep1_ch1() { return ep1_.cd1_.ch_.get(); }
    cricket::P2PTransportChannel* ep1_ch2() { return ep1_.cd2_.ch_.get(); }
    cricket::P2PTransportChannel* ep2_ch1() { return ep2_.cd1_.ch_.get(); }
    cricket::P2PTransportChannel* ep2_ch2() { return ep2_.cd2_.ch_.get(); }

    // Common results.
    static const Result kLocalUdpToLocalUdp;
    static const Result kLocalUdpToStunUdp;
    static const Result kLocalUdpToPrflxUdp;
    static const Result kPrflxUdpToLocalUdp;
    static const Result kStunUdpToLocalUdp;
    static const Result kStunUdpToStunUdp;
    static const Result kPrflxUdpToStunUdp;
    static const Result kLocalUdpToRelayUdp;
    static const Result kPrflxUdpToRelayUdp;
    static const Result kLocalTcpToLocalTcp;
    static const Result kLocalTcpToPrflxTcp;
    static const Result kPrflxTcpToLocalTcp;

    static void SetUpTestCase() {
        // Ensure the RNG is inited.
        talk_base::InitRandom(NULL, 0);
    }

    talk_base::NATSocketServer* nat() { return nss_.get(); }
    talk_base::FirewallSocketServer* fw() { return ss_.get(); }

    Endpoint* GetEndpoint(int endpoint) {
        if (endpoint == 0) {
            return &ep1_;
        } else if (endpoint == 1) {
            return &ep2_;
        } else {
            return NULL;
        }
    }
    cricket::PortAllocator* GetAllocator(int endpoint) {
        return GetEndpoint(endpoint)->allocator_.get();
    }




    void OnChannelRequestSignaling(cricket::TransportChannelImpl* channel) {
        channel->OnSignalingReady();
    }
    // We pass the candidates directly to the other side.
    void OnCandidate(cricket::TransportChannelImpl* ch,
                     const cricket::Candidate& c) {
        main_->PostDelayed(GetEndpoint(ch)->signaling_delay_, this, 0,
                           new CandidateData(ch, c));
    }
    void OnMessage(talk_base::Message* msg) {
        talk_base::scoped_ptr<CandidateData> data(
                    static_cast<CandidateData*>(msg->pdata));
        cricket::P2PTransportChannel* rch = GetRemoteChannel(data->channel);
        cricket::Candidate c = data->candidate;
        if (clear_remote_candidates_ufrag_pwd_) {
            c.set_username("");
            c.set_password("");
        }
        LOG(LS_INFO) << "Candidate(" << data->channel->component() << "->"
                     << rch->component() << "): " << c.type() << ", " << c.protocol()
                     << ", " << c.address().ToString() << ", " << c.username()
                     << ", " << c.generation();
        rch->OnCandidate(c);
    }
    void OnReadPacket(cricket::TransportChannel* channel, const char* data,
                      size_t len, const talk_base::PacketTime& packet_time,
                      int flags) {
        std::list<std::string>& packets = GetPacketList(channel);
        packets.push_front(std::string(data, len));
    }
    void OnRoleConflict(cricket::TransportChannelImpl* channel) {
        GetEndpoint(channel)->OnRoleConflict(true);
        cricket::IceRole new_role =
                GetEndpoint(channel)->ice_role() == cricket::ICEROLE_CONTROLLING ?
                    cricket::ICEROLE_CONTROLLED : cricket::ICEROLE_CONTROLLING;
        channel->SetIceRole(new_role);
    }
    int SendData(cricket::TransportChannel* channel,
                 const char* data, size_t len) {
        return channel->SendPacket(data, len, talk_base::DSCP_NO_CHANGE, 0);
    }
    bool CheckDataOnChannel(cricket::TransportChannel* channel,
                            const char* data, int len) {
        return GetChannelData(channel)->CheckData(data, len);
    }
    static const cricket::Candidate* LocalCandidate(
            cricket::P2PTransportChannel* ch) {
        return (ch && ch->best_connection()) ?
                    &ch->best_connection()->local_candidate() : NULL;
    }
    static const cricket::Candidate* RemoteCandidate(
            cricket::P2PTransportChannel* ch) {
        return (ch && ch->best_connection()) ?
                    &ch->best_connection()->remote_candidate() : NULL;
    }
    Endpoint* GetEndpoint(cricket::TransportChannel* ch) {
        if (ep1_.HasChannel(ch)) {
            return &ep1_;
        } else if (ep2_.HasChannel(ch)) {
            return &ep2_;
        } else {
            return NULL;
        }
    }
    cricket::P2PTransportChannel* GetRemoteChannel(
            cricket::TransportChannel* ch) {
        if (ch == ep1_ch1())
            return ep2_ch1();
        else if (ch == ep1_ch2())
            return ep2_ch2();
        else if (ch == ep2_ch1())
            return ep1_ch1();
        else if (ch == ep2_ch2())
            return ep1_ch2();
        else
            return NULL;
    }
    std::list<std::string>& GetPacketList(cricket::TransportChannel* ch) {
        return GetChannelData(ch)->ch_packets_;
    }

    void set_clear_remote_candidates_ufrag_pwd(bool clear) {
        clear_remote_candidates_ufrag_pwd_ = clear;
    }

private:
    talk_base::Thread* main_;
    talk_base::scoped_ptr<talk_base::PhysicalSocketServer> pss_;
    talk_base::scoped_ptr<talk_base::VirtualSocketServer> vss_;
    talk_base::scoped_ptr<talk_base::NATSocketServer> nss_;
    talk_base::scoped_ptr<talk_base::FirewallSocketServer> ss_;
    talk_base::SocketServerScope ss_scope_;
    cricket::TestStunServer stun_server_;
    cricket::TestRelayServer relay_server_;
    talk_base::SocksProxyServer socks_server1_;
    talk_base::SocksProxyServer socks_server2_;
    Endpoint ep1_;
    Endpoint ep2_;
    bool clear_remote_candidates_ufrag_pwd_;
};

#endif // CHANNELTEST_H
