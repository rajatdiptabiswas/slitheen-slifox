#include <iostream>

#include "prio.h"
#include "nsHttpSlitheenConnector.h"

namespace mozilla {
namespace net {

nsHttpSlitheenConnector* nsHttpSlitheenConnector::smConnector = nullptr;

nsHttpSlitheenConnector::
nsHttpSlitheenConnector() :
    mThread(nullptr),
    mSocketLock(nullptr),
    mSocket(nullptr),
    mChildSocket(nullptr),
    mUpstreamLock(nullptr)
{
    std::cerr << "Creating Slitheen Connector " << (void *)this << "\n";

    mSocketLock = PR_NewLock();
    mUpstreamLock = PR_NewLock();

    smConnector = this;
}

nsHttpSlitheenConnector::
~nsHttpSlitheenConnector()
{
    std::cerr << "Destroying Slitheen Connector " << (void *)this << "\n";

    smConnector = nullptr;

    PR_DestroyLock(mSocketLock);
    mSocketLock = nullptr;
    PR_DestroyLock(mUpstreamLock);
    mUpstreamLock = nullptr;
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

    PR_Lock(mSocketLock);
    if (mChildSocket) {
        PR_Close(mChildSocket);
        mChildSocket = nullptr;
    }
    if (mSocket) {
        PR_Close(mSocket);
        mSocket = nullptr;
    }
    PR_Unlock(mSocketLock);

    // join with thread
    PR_JoinThread(mThread);
    mThread = nullptr;

    std::cerr << "Shutdown Slitheen Connector (joined) " << (void *)this << "\n";
}

// Read the full given amount of data from the PRFileDesc*, even if it
// blocks
static
PRInt32
PR_Read_Fully(PRFileDesc *fd, void *vbuf, PRInt32 amount)
{
    unsigned char *buf = (unsigned char *)vbuf;
    PRInt32 totread = 0;

    if (amount < 0) {
        return -1;
    }
    while (amount > 0) {
        PRInt32 res = PR_Read(fd, buf, amount);
        if (res <= 0) {
            return res;
        }
        buf += res;
        amount -= res;
        totread += res;
    }
    return totread;
}

// Read a 2-byte length then that many bytes of data from a PRFileDesc*
// and set the given string to the result.  Returns false if EOF or a
// read error has occurred, true otherwise.
static
bool
readString(PRFileDesc *fd, nsCString &str)
{
    unsigned char chunklenbuf[2];
    PRInt32 res = PR_Read_Fully(fd, chunklenbuf, 2);
    if (res < 2) return false;
    PRInt32 chunklen = (PRInt32(chunklenbuf[0]) << 8) | PRInt32(chunklenbuf[1]);
    char *buf = new char[chunklen];
    if (!buf) return false;
    res = PR_Read_Fully(fd, buf, chunklen);
    if (res < chunklen) {
        delete[] buf;
        return false;
    }
    str.Assign(buf, chunklen);
    delete[] buf;
    return true;
}

void
nsHttpSlitheenConnector::
mainloop()
{
    while(mSocket != nullptr) {
        mChildSocket = PR_Accept(mSocket, nullptr,
                                    PR_INTERVAL_NO_TIMEOUT);
        if (!mChildSocket) {
            PR_Lock(mSocketLock);
            if (mSocket) {
                PR_Close(mSocket);
                mSocket = nullptr;
            }
            PR_Unlock(mSocketLock);
            return;
        }

        // The first string we read is the Slitheen ID
        PR_Lock(mUpstreamLock);
        bool ok = readString(mChildSocket, mSlitheenID);
        PR_Unlock(mUpstreamLock);

        if (!ok) {
            PR_Lock(mSocketLock);
            if (mChildSocket) {
                PR_Close(mChildSocket);
                mChildSocket = nullptr;
            }
            PR_Unlock(mSocketLock);
            continue;
        }

        while(1) {
            nsCString str;
            ok = readString(mChildSocket, str);
            if (!ok) {
                PR_Lock(mSocketLock);
                if (mChildSocket) {
                    PR_Close(mChildSocket);
                    mChildSocket = nullptr;
                }
                PR_Unlock(mSocketLock);
                break;
            }
            PR_Lock(mUpstreamLock);
            mUpstreamQueue.push(str);
            PR_Unlock(mUpstreamLock);
        }
    }
}

nsresult
nsHttpSlitheenConnector::getHeader(nsCString &header)
{
    return NS_OK;
}


} // namespace net
} // namespace mozilla
