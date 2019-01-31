
#include "mozilla/dom/ContentChild.h"
#include "nsWeakReference.h"
#include "nsIStreamListener.h"
#include "nsIInputStream.h"
#include "nsISupports.h"
#include "nsIThread.h"
#include "nsIThreadManager.h"
#include "nsServiceManagerUtils.h"
#include "nsCURILoader.h"
#include "prio.h"
#include "nsHttpSlitheenConnector.h"
#include "SlitheenConnectorChild.h"

#include <iostream>
#define SLITHEEN_CONTENT_TYPE "sli/theen"

namespace mozilla {
namespace net {

NS_IMPL_ISUPPORTS(SlitheenStreamListener, nsIStreamListener)

SlitheenStreamListener::
SlitheenStreamListener()
{

    mConnectorChild = nullptr;
    // std::cerr << "SlitheenStreamListener ctor " << this << "\n";
    if(XRE_IsContentProcess()) {
        std::cerr << "New stream listener in content process\n";


    } else {
        std::cerr << "New stream listener in parent process\n";
    }
}

SlitheenStreamListener::
~SlitheenStreamListener()
{
}

NS_IMETHODIMP
SlitheenStreamListener::
OnDataAvailable(nsIRequest *aRequest, nsISupports *aContext,
    nsIInputStream *aInputStream, uint64_t aOffset, uint32_t aCount)
{
    uint32_t ret;
    nsresult rv;

    char *buf = new char[aCount];
    if (!buf) {
        return NS_ERROR_OUT_OF_MEMORY;
    }
    rv = aInputStream->Read(buf, aCount, &ret);
    if (NS_FAILED(rv)) {
        return rv;
    }
    mData.Append(buf, aCount);
    delete[] buf;
    return NS_OK;
}

NS_IMETHODIMP
SlitheenStreamListener::
OnStartRequest(nsIRequest *aRequest, nsISupports *aContext)
{
    return NS_OK;
}

NS_IMETHODIMP
SlitheenStreamListener::
OnStopRequest(nsIRequest *aRequest, nsISupports *aContext,
    nsresult aStatusCode)
{
    // std::cerr << "OnStopRequest called\n";

    //If it's a child, send to parent
    if (XRE_IsContentProcess()) {
        //std::cerr << "SlitheenStreamListener::OnStopRequest (child pid " << getpid() << ")\n";

        using mozilla::dom::ContentChild;
        ContentChild *child = ContentChild::GetSingleton();
        if (child) {
            PSlitheenConnectorChild *pc =
                child->SendPSlitheenConnectorConstructor();

            mConnectorChild = static_cast<SlitheenConnectorChild *>(pc);

        } else {
            std::cerr << "Failed to get child. pid = " << getpid() << "\n";
        }

        if (mConnectorChild) {
            mConnectorChild->SendOnSlitheenResource(mData);
        }
        mData.Assign("");

    } else if (XRE_IsParentProcess()) {

        //std::cerr << "SlitheenStreamListener::OnStopRequest (parent pid " << getpid() << ")\n";
        nsHttpSlitheenConnector *connector =
            nsHttpSlitheenConnector::getInstance();
        if (connector) {
            connector->OnSlitheenResource(mData);
            mData.Assign("");
        }
    }

    return NS_OK;
}

///// END OF SlitheenStreamListener /////

// Next we define the Slitheen Content Listener
class SlitheenContentListener final : public nsIURIContentListener
                                    , public nsSupportsWeakReference
{
public:
    NS_DECL_THREADSAFE_ISUPPORTS
    NS_DECL_NSIURICONTENTLISTENER

    SlitheenContentListener();

private:
    ~SlitheenContentListener();

    nsCOMPtr<nsIStreamListener> mListener;
};

NS_IMPL_ISUPPORTS(SlitheenContentListener,
                  nsIURIContentListener,
                  nsISupportsWeakReference)

SlitheenContentListener::
SlitheenContentListener()
{
}

SlitheenContentListener::
~SlitheenContentListener()
{
}

NS_IMETHODIMP
SlitheenContentListener::
OnStartURIOpen(nsIURI *aURI, bool *aAbortOpen)
{
    *aAbortOpen = false;  // Do not block the loading of this content

    return NS_OK;
}

NS_IMETHODIMP
SlitheenContentListener::
DoContent(const nsACString &aContentType,
    bool aIsContentPreferred, nsIRequest *aRequest,
    nsIStreamListener **aContentHandler, bool *_retval)
{

    mListener = new SlitheenStreamListener();
    NS_IF_ADDREF(*aContentHandler = mListener);

    return NS_OK;
}

NS_IMETHODIMP
SlitheenContentListener::
IsPreferred(const char *aContentType,
    char **aDesiredContentType, bool *aPreferred)
{
    if (!strcmp(aContentType, SLITHEEN_CONTENT_TYPE)) {
        *aPreferred = true;
        *aDesiredContentType = nullptr;
    } else {
        *aPreferred = false;
    }
    return NS_OK;
}

NS_IMETHODIMP
SlitheenContentListener::
CanHandleContent(const char *aContentType,
    bool aIsContentPreferred, char **aDesiredContentType, bool *aCanHandle)
{
    return IsPreferred(aContentType, aDesiredContentType, aCanHandle);
}

NS_IMETHODIMP
SlitheenContentListener::
GetLoadCookie(nsISupports **aLoadCookie)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
SetLoadCookie(nsISupports *aLoadCookie)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
GetParentContentListener(
    nsIURIContentListener **aParentContentListener)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
SetParentContentListener(
    nsIURIContentListener *aParentContentListener)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

///// END OF SlitheenStreamListener /////

nsHttpSlitheenConnector* nsHttpSlitheenConnector::smConnector = nullptr;
nsISlitheenSupercryptor* nsHttpSlitheenConnector::smSlitheenSupercryptor = nullptr;

nsHttpSlitheenConnector::
nsHttpSlitheenConnector() :
    mContentListener(nullptr),
    mThread(nullptr),
    mSocketLock(nullptr),
    mSocket(nullptr),
    mChildSocket(nullptr),
    mUpstreamLock(nullptr)
{

    mSocketLock = PR_NewRWLock(0, "SocketLock");
    mUpstreamLock = PR_NewRWLock(1, "UpstreamLock");

    smConnector = this;
}

nsHttpSlitheenConnector::
~nsHttpSlitheenConnector()
{

    smConnector = nullptr;

    PR_DestroyRWLock(mSocketLock);
    mSocketLock = nullptr;
    PR_DestroyRWLock(mUpstreamLock);
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
    nsresult nsrv;

    // Register the SlitheenContentListener as a handler for the
    // downstream slitheen data type
    nsCOMPtr<nsIURILoader>
        uriLoader(do_GetService(NS_URI_LOADER_CONTRACTID, &nsrv));
    if (NS_FAILED(nsrv)) {
        return false;
    }
    mContentListener = new SlitheenContentListener();
    nsrv = uriLoader->RegisterContentListener(mContentListener);

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

    if (mSocket) {
        PR_Close(mSocket);
        mSocket = nullptr;
    }
    if (mChildSocket) {
        PR_Close(mChildSocket);  // This will cause the reader to stop
                                 // listening on the socket and release
                                 // its reader lock
        PR_RWLock_Wlock(mSocketLock);
        mChildSocket = nullptr;
        PR_RWLock_Unlock(mSocketLock);
    }

    // join with thread
    PR_JoinThread(mThread);
    mThread = nullptr;

    // Deegister the SlitheenContentListener as a handler for the
    // downstream slitheen data type
    nsresult nsrv;
    nsCOMPtr<nsIURILoader>
        uriLoader(do_GetService(NS_URI_LOADER_CONTRACTID, &nsrv));
    if (NS_SUCCEEDED(nsrv)) {
        uriLoader->UnRegisterContentListener(mContentListener);
    }
    mContentListener = nullptr;
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

// Write the full given amount of data to the PRFileDesc*, even if it
// blocks
static
PRInt32
PR_Write_Fully(PRFileDesc *fd, const void *vbuf, PRInt32 amount)
{
    const unsigned char *buf = (const unsigned char *)vbuf;
    PRInt32 totwritten = 0;

    if (amount < 0) {
        return -1;
    }
    while (amount > 0) {
        PRInt32 res = PR_Write(fd, buf, amount);
        if (res <= 0) {
            return res;
        }
        buf += res;
        amount -= res;
        totwritten += res;
    }
    return totwritten;
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

// Write a 4-byte length then that many bytes of data to a PRFileDesc*.
// Returns false if EOF or a write error has occurred, true otherwise.
static
bool
writeString(PRFileDesc *fd, const nsCString &str)
{
    unsigned char chunklenbuf[4];
    PRInt32 chunklen = str.Length();
    chunklenbuf[0] = (chunklen & 0xff);
    chunklenbuf[1] = ((chunklen >> 8) & 0xff);
    chunklenbuf[2] = ((chunklen >> 16) & 0xff);
    chunklenbuf[3] = ((chunklen >> 24) & 0xff);
    PRInt32 res = PR_Write_Fully(fd, chunklenbuf, 4);
    if (res < 4) return false;
    res = PR_Write_Fully(fd, str.get(), chunklen);
    if (res < chunklen) {
        return false;
    }
    return true;
}

void
nsHttpSlitheenConnector::
mainloop()
{
    while(mSocket != nullptr) {
        PRFileDesc *childsocket = PR_Accept(mSocket, nullptr,
                                            PR_INTERVAL_NO_TIMEOUT);
        if (!childsocket) {
            if (mSocket) {
                PRFileDesc *mastersocket = mSocket;
                mSocket = nullptr;
                PR_Close(mastersocket);
            }
            return;
        }
        PR_RWLock_Wlock(mSocketLock);
        mChildSocket = childsocket;
        PR_RWLock_Unlock(mSocketLock);

        // The first string we read is the Slitheen ID
        PR_RWLock_Rlock(mSocketLock);
        PR_RWLock_Wlock(mUpstreamLock);
        bool ok = readString(mChildSocket, mSlitheenID);
        PR_RWLock_Unlock(mUpstreamLock);
        PR_RWLock_Unlock(mSocketLock);

        if (!ok) {
            PR_RWLock_Wlock(mSocketLock);
            if (mChildSocket) {
                PR_Close(mChildSocket);
                mChildSocket = nullptr;
            }
            PR_RWLock_Unlock(mSocketLock);
            continue;
        }

        while(1) {
            nsCString str;
            ok = false;
            PR_RWLock_Rlock(mSocketLock);
            if (mChildSocket) {
                ok = readString(mChildSocket, str);
            }
            PR_RWLock_Unlock(mSocketLock);
            if (!ok) {
                PR_RWLock_Wlock(mSocketLock);
                if (mChildSocket) {
                    PR_Close(mChildSocket);
                    mChildSocket = nullptr;
                    PR_RWLock_Wlock(mUpstreamLock);
                    mSlitheenID.Assign("");
                    PR_RWLock_Unlock(mUpstreamLock);
                }
                PR_RWLock_Unlock(mSocketLock);
                break;
            }
            PR_RWLock_Wlock(mUpstreamLock);
            mUpstreamQueue.push(str);
            PR_RWLock_Unlock(mUpstreamLock);
        }
    }
}

nsresult
nsHttpSlitheenConnector::
getHeader(nsISlitheenSupercryptor *supercryptor, nsCString &header)
{
    nsresult rv = NS_ERROR_NOT_INITIALIZED;

    PR_RWLock_Wlock(mUpstreamLock);
    if (smSlitheenSupercryptor == nullptr) {
        smSlitheenSupercryptor = supercryptor;
    }
    if (mSlitheenID.Length() > 0) {
        header.Assign("X-Slitheen: ");
        header.Append(mSlitheenID);
        while (!mUpstreamQueue.empty()) {
            header.Append(" ");
            header.Append(mUpstreamQueue.front());
            mUpstreamQueue.pop();
        }
        header.Append("\r\n");
        rv = NS_OK;
    }
    PR_RWLock_Unlock(mUpstreamLock);
    return rv;
}

nsresult
nsHttpSlitheenConnector::
OnSlitheenResource(const nsCString &resource)
{
    std::cerr << "Slitheen resource received: (" << resource.Length() << " bytes)\n";
    // For now, just write the data to the socket, and assume the SOCKS
    // proxy is reading fast enough that this won't block (because we're
    // in the socket thread).
    bool ok = false;
    if (mChildSocket) {
        PR_RWLock_Rlock(mSocketLock);
        // mChildSocket may have changed by the time we get the lock
        if (mChildSocket) {
            ok = writeString(mChildSocket, resource);
        }
        PR_RWLock_Unlock(mSocketLock);
    }
    if (!ok) {
        // The read side of the socket should fail as well, so we'll let
        // that side handle closing and resetting the socket.  For now,
        // this resource will just be lost.
        std::cerr << "Slitheen resource lost due to error writing to SOCKS proxy\n";
    }
    return NS_OK;
}

void
nsHttpSlitheenConnector::
SendSlitheenResource(nsCString data)
{
    SlitheenConnectorChild *connectorChild;

    using mozilla::dom::ContentChild;
    ContentChild *child = ContentChild::GetSingleton();

    if (child) {

        PSlitheenConnectorChild *pc =
            child->SendPSlitheenConnectorConstructor();
        connectorChild = static_cast<SlitheenConnectorChild *>(pc);

        if (connectorChild) {
            connectorChild->SendOnSlitheenResource(data);
        }

    } else {
        std::cerr << "Failed to get child. pid = " << getpid() << "\n";
    }

}

nsresult
nsHttpSlitheenConnector::
ReceiveResource(nsCString resource)
{
    //If it's a child, send to parent
    if (XRE_IsContentProcess()) {

        RefPtr<Runnable> runnable =
            NS_NewRunnableFunction("net::nsHttpSlitheenConnector::SendSlitheenResource",[resource]() {
                    net::nsHttpSlitheenConnector::SendSlitheenResource(resource);
                    });

        using mozilla::dom::ContentChild;
        ContentChild *child = ContentChild::GetSingleton();

        if (child) {
            child->GetIPCChannel()->GetWorkerLoop()->PostTask(runnable.forget());
        }
    } else if (XRE_IsParentProcess()) {
        nsHttpSlitheenConnector *connector =
            nsHttpSlitheenConnector::getInstance();
        if (connector) {
            connector->OnSlitheenResource(resource);
        }
    }

    return NS_OK;
}

} // namespace net
} // namespace mozilla
