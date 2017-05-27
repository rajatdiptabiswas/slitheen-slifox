#include <iostream>

#include "prio.h"
#include "nsHttpSlitheenConnector.h"

namespace mozilla {
namespace net {

nsHttpSlitheenConnector::
nsHttpSlitheenConnector() :
    mLock(nullptr),
    mThread(nullptr),
    mSocket(nullptr),
    mChildSocket(nullptr)
{
    std::cerr << "Creating Slitheen Connector " << (void *)this << "\n";

    mLock = PR_NewLock();
}

nsHttpSlitheenConnector::
~nsHttpSlitheenConnector()
{
    std::cerr << "Destroying Slitheen Connector " << (void *)this << "\n";

    PR_DestroyLock(mLock);
    mLock = nullptr;
}

static void slitheen_run(void *arg)
{
    nsHttpSlitheenConnector *obj = (nsHttpSlitheenConnector*)arg;
    obj->mainloop();
}

bool
nsHttpSlitheenConnector::
Init(unsigned short port)
{
    PRStatus rv;

    std::cerr << "Init Slitheen Connector " << (void *)this << " port " << port << "\n";

    // Create the socket
    PRFileDesc *socket = PR_OpenTCPSocket(AF_INET);
    if (socket == nullptr) {
        return false;
    }

    // Set REUSEADDR
    PRSocketOptionData optd;
    optd.option = PR_SockOpt_Reuseaddr;
    optd.value.reuse_addr = 1;
    PR_SetSocketOption(socket, &optd);

    // Bind and listen on the port
    PRNetAddr addr;
    addr.inet.family = AF_INET;
    addr.inet.port = htons(port);
    addr.inet.ip = htonl(0x7f000001);
    rv = PR_Bind(socket, &addr);
    if (rv != PR_SUCCESS) {
        perror("bind");
        return false;
    }
    PR_Listen(socket, 5);

    mSocket = socket;

    mThread = PR_CreateThread(PR_USER_THREAD, slitheen_run, this,
        PR_PRIORITY_NORMAL, PR_LOCAL_THREAD, PR_JOINABLE_THREAD,
        1<<20);

    return (mThread != nullptr);
}

void
nsHttpSlitheenConnector::
Shutdown()
{
    std::cerr << "Shutdown Slitheen Connector (joining) " << (void *)this << "\n";

    PR_Lock(mLock);
    if (mChildSocket) {
        PR_Close(mChildSocket);
        mChildSocket = nullptr;
    }
    if (mSocket) {
        PR_Close(mSocket);
        mSocket = nullptr;
    }
    PR_Unlock(mLock);

    // join with thread
    PR_JoinThread(mThread);
    mThread = nullptr;

    std::cerr << "Shutdown Slitheen Connector (joined) " << (void *)this << "\n";
}

void
nsHttpSlitheenConnector::
mainloop()
{
    while(mSocket != nullptr) {
        mChildSocket = PR_Accept(mSocket, nullptr,
                                    PR_INTERVAL_NO_TIMEOUT);
        if (!mChildSocket) {
            PR_Lock(mLock);
            if (mSocket) {
                PR_Close(mSocket);
                mSocket = nullptr;
            }
            PR_Unlock(mLock);
            return;
        }
        while(1) {
            unsigned char chunklen[2];
            PRInt32 res = PR_Read(mChildSocket, chunklen, 2);
            if (res <= 0) {
                PR_Lock(mLock);
                if (mChildSocket) {
                    PR_Close(mChildSocket);
                    mChildSocket = nullptr;
                }
                PR_Unlock(mLock);
                break;
            }
        }
    }
}


} // namespace net
} // namespace mozilla
