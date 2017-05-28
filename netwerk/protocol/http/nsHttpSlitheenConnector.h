#ifndef nsHttpSlitheenConnector_h__
#define nsHttpSlitheenConnector_h__

#include "prthread.h"

namespace mozilla {
namespace net {

class nsHttpSlitheenConnector final
{
public:
    //-------------------------------------------------------------------------
    // NOTE: functions below may only be called on the main thread.
    //-------------------------------------------------------------------------

    nsHttpSlitheenConnector();

    bool Init(unsigned short port);

    void Shutdown();

    //-------------------------------------------------------------------------
    // NOTE: functions below are called from the Slitheen thread
    //-------------------------------------------------------------------------

    void mainloop();

private:
    virtual ~nsHttpSlitheenConnector();

    PRThread *mThread;         // the Slitheen thread

    PRLock *mSocketLock;       // a lock protecting mSocket and
                               //   mChildSocket

    PRFileDesc *mSocket;       // the bound socket, being accept()ed on
    PRFileDesc *mChildSocket;  // the accepted socket; we only have one
                               //   active connection at a time

    friend class nsAutoPtr<nsHttpSlitheenConnector>; // needs to call the destructor
};

} // namespace net
} // namespace mozilla

#endif // nsHttpSlitheenConnector_h__
