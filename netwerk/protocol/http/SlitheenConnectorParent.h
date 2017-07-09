#ifndef SlitheenConnectorParent_h__
#define SlitheenConnectorParent_h__

#include "mozilla/net/PSlitheenConnectorParent.h"

namespace mozilla {
namespace net {

class SlitheenConnectorParent : public PSlitheenConnectorParent
{
public:

    SlitheenConnectorParent();

    //Receive Slitheen resources from SlitheenStreamListeners in other processes
    mozilla::ipc::IPCResult RecvOnSlitheenResource(const nsCString &resource);

private:
    bool mIPCClosed;

    virtual ~SlitheenConnectorParent();

    virtual void ActorDestroy(ActorDestroyReason why) override;

    void Delete();

};

} // namespace net
} // namespace mozilla

#endif //SlitheenConnectorParent_h__
