
#include "SlitheenConnectorParent.h"

namespace mozilla {
namespace net {

SlitheenConnectorParent::
SlitheenConnectorParent():
    mIPCClosed(false)
{
}

SlitheenConnectorParent::
~SlitheenConnectorParent()
{
}

mozilla::ipc::IPCResult
SlitheenConnectorParent::
RecvOnSlitheenResource(const nsCString &resource)
{
    //std::cerr << "RecvSlitheenResource called at parent: (" << resource.Length() << " bytes)\n";
    nsHttpSlitheenConnector *connector =
        nsHttpSlitheenConnector::getInstance();
    if (connector) {
        connector->OnSlitheenResource(resource);
    }

    //Finally, delete protocol
    Delete();

    return IPC_OK();

}

void
SlitheenConnectorParent::
ActorDestroy(ActorDestroyReason why)
{
    mIPCClosed = true;
}

void
SlitheenConnectorParent::
Delete()
{
    if (!mIPCClosed) {
        Unused << Send__delete__(this);
    }
}

} // namespace net
} // namespace mozilla
