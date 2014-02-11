#ifndef MYCONDUCTOR_H
#define MYCONDUCTOR_H

#include "talk/app/kaerp2p/KaerSession.h"
#include "peer_connection_client.h"
namespace kaerp2p {

class MyConductor:
        public webrtc::CreateSessionDescriptionObserver,
        public IceObserver,public PeerConnectionClientObserver
{
public:
    enum CallbackID {
        MEDIA_CHANNELS_INITIALIZED = 1,
        PEER_CONNECTION_CLOSED,
        SEND_MESSAGE_TO_PEER,
        PEER_CONNECTION_ERROR,
        NEW_STREAM_ADDED,
        STREAM_REMOVED,
    };

    MyConductor(PeerConnectionClient* client);

    virtual void StartLogin(const std::string& server, int port);
    virtual void DisconnectFromServer();
    virtual void ConnectToPeer(int peer_id);
    virtual void DisconnectFromCurrentPeer();
protected:
    bool InitializePeerConnection();
    void DeletePeerConnection();
    int peer_id_;
    PeerConnectionClient* client_;
    std::deque<std::string*> pending_messages_;
    std::string server_;
    talk_base::scoped_ptr<KaerSession> session_;
    talk_base::BasicNetworkManager network_manager_;
    talk_base::scoped_ptr<cricket::PortAllocator> allocator_;

    // CreateSessionDescriptionObserver interface
public:
    void OnSuccess(SessionDescriptionInterface *desc);
    void OnFailure(const std::string &error);

    // IceObserver interface
public:
    void OnIceConnectionChange(IceConnectionState new_state){};
    void OnIceGatheringChange(IceGatheringState new_state){};
    void OnIceCandidate(const IceCandidateInterface *candidate);
    void OnIceComplete(){};

    void OnSignedIn();
    void OnDisconnected();
    void OnPeerConnected(int id, const std::string &name);
    void OnPeerDisconnected(int peer_id);
    void OnMessageFromPeer(int peer_id, const std::string &message);
    void OnMessageSent(int err);
    void OnServerConnectionFailure();

    void UIThreadCallback(int msg_id, void* data);

};

}
#endif // MYCONDUCTOR_H
