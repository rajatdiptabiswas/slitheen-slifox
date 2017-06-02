#include <iostream>

#include "nsWeakReference.h"
#include "nsIStreamListener.h"
#include "nsIInputStream.h"
#include "nsServiceManagerUtils.h"
#include "nsCURILoader.h"
#include "prio.h"
#include "nsHttpSlitheenConnector.h"

#define SLITHEEN_CONTENT_TYPE "sli/theen"

namespace mozilla {
namespace net {

// First we define the StreamListener that will receive downstream
// Slitheen data
class SlitheenStreamListener final : public nsIStreamListener
{
public:
    NS_DECL_THREADSAFE_ISUPPORTS
    NS_DECL_NSIREQUESTOBSERVER
    NS_DECL_NSISTREAMLISTENER

    SlitheenStreamListener();

private:
    virtual ~SlitheenStreamListener();

    nsCString mData;
};

NS_IMPL_ISUPPORTS(SlitheenStreamListener, nsIStreamListener)

SlitheenStreamListener::
SlitheenStreamListener()
{
std::cerr << "SlitheenStreamListener ctor\n";
}

SlitheenStreamListener::
~SlitheenStreamListener()
{
std::cerr << "SlitheenStreamListener dtor\n";
}

NS_IMETHODIMP
SlitheenStreamListener::
OnDataAvailable(nsIRequest *aRequest, nsISupports *aContext,
    nsIInputStream *aInputStream, uint64_t aOffset, uint32_t aCount)
{
    uint32_t ret;
    nsresult rv;

    std::cerr << "OnDataAvailable called with aCount = " << aCount << "\n";
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
    std::cerr << "OnStartRequest called\n";
    return NS_OK;
}

NS_IMETHODIMP
SlitheenStreamListener::
OnStopRequest(nsIRequest *aRequest, nsISupports *aContext,
    nsresult aStatusCode)
{
    std::cerr << "OnStopRequest called\n";
    nsHttpSlitheenConnector *connector =
        nsHttpSlitheenConnector::getInstance();
    if (connector) {
        connector->OnSlitheenResource(mData);
        mData.Assign("");
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

NS_IMPL_ISUPPORTS(SlitheenContentListener, nsIURIContentListener, nsISupportsWeakReference)

SlitheenContentListener::
SlitheenContentListener()
{
std::cerr << "SlitheenContentListener ctor\n";
}

SlitheenContentListener::
~SlitheenContentListener()
{
std::cerr << "SlitheenContentListener dtor\n";
}

NS_IMETHODIMP
SlitheenContentListener::
OnStartURIOpen(nsIURI *aURI, bool *aAbortOpen)
{
    std::cerr << "OnStartURLOpen called\n";
    *aAbortOpen = false;  // Do not block the loading of this content

    return NS_OK;
}

NS_IMETHODIMP
SlitheenContentListener::
DoContent(const nsACString &aContentType,
    bool aIsContentPreferred, nsIRequest *aRequest,
    nsIStreamListener **aContentHandler, bool *_retval)
{
    std::cerr << "DoContent called\n";

    mListener = new SlitheenStreamListener();
    NS_IF_ADDREF(*aContentHandler = mListener);

    return NS_OK;
}

NS_IMETHODIMP
SlitheenContentListener::
IsPreferred(const char *aContentType,
    char **aDesiredContentType, bool *aPreferred)
{
    std::cerr << "Asked for IsPreferred " << aContentType << "\n";
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
    std::cerr << "GetLoadCookie called\n";
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
SetLoadCookie(nsISupports *aLoadCookie)
{
    std::cerr << "SetLoadCookie called\n";
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
GetParentContentListener(
    nsIURIContentListener **aParentContentListener)
{
    std::cerr << "GetParentContentListener called\n";
    return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
SlitheenContentListener::
SetParentContentListener(
    nsIURIContentListener *aParentContentListener)
{
    std::cerr << "SetParentContentListener called\n";
    return NS_ERROR_NOT_IMPLEMENTED;
}

///// END OF SlitheenStreamListener /////

nsHttpSlitheenConnector* nsHttpSlitheenConnector::smConnector = nullptr;

nsHttpSlitheenConnector::
nsHttpSlitheenConnector() :
    mContentListener(nullptr),
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
    nsresult nsrv;

    std::cerr << "Init Slitheen Connector " << (void *)this << " port " << port << "\n";

    // Register the SlitheenContentListener as a handler for the
    // downstream slitheen data type
    nsCOMPtr<nsIURILoader>
        uriLoader(do_GetService(NS_URI_LOADER_CONTRACTID, &nsrv));
    if (NS_FAILED(nsrv)) {
        std::cerr << "Failed to look up URI Loader\n";
        return false;
    }
    NS_IF_ADDREF(mContentListener = new SlitheenContentListener());
    nsrv = uriLoader->RegisterContentListener(mContentListener);
    if (NS_FAILED(nsrv)) {
        std::cerr << "Failed to register content listener\n";
    } else {
        std::cerr << "Registered content listener " << this << "\n";
    }

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

    // Deegister the SlitheenContentListener as a handler for the
    // downstream slitheen data type
    nsresult nsrv;
    nsCOMPtr<nsIURILoader>
        uriLoader(do_GetService(NS_URI_LOADER_CONTRACTID, &nsrv));
    if (NS_SUCCEEDED(nsrv)) {
        uriLoader->UnRegisterContentListener(mContentListener);
    }
    mContentListener = nullptr;
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
                    mSlitheenID.Assign("");
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
nsHttpSlitheenConnector::
getHeader(nsCString &header)
{
    nsresult rv = NS_ERROR_NOT_INITIALIZED;

    PR_Lock(mUpstreamLock);
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
    PR_Unlock(mUpstreamLock);
    return rv;
}

nsresult
nsHttpSlitheenConnector::
OnSlitheenResource(const nsCString &resource)
{
std::cerr << "Slitheen resource received: [" << resource.get() << "]\n";
    return NS_OK;
}

} // namespace net
} // namespace mozilla
