#ifndef SlitheenConnectorParent_h__
#define SlitheenConnectorParent_h__

#include "mozilla/net/PSlitheenConnectorParent.h"

namespace mozilla {
namespace net {

class SlitheenConnectorParent : public PSlitheenConnectorParent
{
public:

    SlitheenConnectorParent();

protected:

    //Receive Slitheen resources from SlitheenStreamListeners in other processes
    virtual bool RecvOnSlitheenResource(const nsCString &resource) override;

private:
    bool mIPCClosed;

    virtual ~SlitheenConnectorParent();

    virtual void ActorDestroy(ActorDestroyReason why) override;

    void Delete();

};

} // namespace net
} // namespace mozilla

#endif //SlitheenConnectorParent_h__
