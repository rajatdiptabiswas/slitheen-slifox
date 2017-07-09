#ifndef SlitheenConnectorChild_h__
#define SlitheenConnectorChild_h__

#include "mozilla/net/PSlitheenConnectorChild.h"

namespace mozilla {
namespace net {

class SlitheenConnectorChild : public PSlitheenConnectorChild
{
public:

    SlitheenConnectorChild();

private:
    virtual ~SlitheenConnectorChild();
};

} // namespace net
} // namespace mozilla

#endif //SlitheenConnectorChild_h__
