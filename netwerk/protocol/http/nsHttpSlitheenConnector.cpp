
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
#include <iomanip>
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

nsHttpSlitheenConnector* nsHttpSlitheenConnector::smConnector = nullptr;
nsISlitheenSupercryptor* nsHttpSlitheenConnector::smSlitheenSupercryptor = nullptr;

nsHttpSlitheenConnector::
nsHttpSlitheenConnector() :
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

// Read the socksBlock header of the supplied buffer and return
// the length of the block
static
PRInt16
chunkLen(char *buf)
{
    // Read the length field of the header to determine the amount of data
    return (PRInt16(buf[3]) << 8) | PRInt16(buf[2]);
}

// Read the block header and then that many bytes of data from a PRFileDesc*
// and set the given string to the result.  Returns false if EOF or a
// read error has occurred, true otherwise.
static
bool
readString(PRFileDesc *fd, nsACString &str)
{
    // We need to read in the 12 byte header first
    char headerbuf[12];
    PRInt32 res = PR_Read_Fully(fd, headerbuf, 12);
    if (res < 12) return false;

    // Read the length field of the header to determine the amount of data
    PRInt16 chunklen = chunkLen(headerbuf);
    char *buf = new char[chunklen+12];

    std::cerr << "Read in header ";
    for (int i=0; i< 12; i++)
	std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) (headerbuf)[i] << " ";
	std::cerr << "\n";

    // We send the full header to the relay station
    memcpy(buf, headerbuf, 12);
    if (!buf) return false;
    res = PR_Read_Fully(fd, buf+4, chunklen);

    std::cerr << "Read in data ";
    for (int i=12; i< chunklen; i++)
	std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) (buf)[i] << " ";
	std::cerr << "\n";

    if (res < chunklen) {
        delete[] buf;
        return false;
    }
	str.Append(buf, chunklen+4);
	delete[] buf;
    return true;
}

// Write a 4-byte length then that many bytes of data to a PRFileDesc*.
// Returns false if EOF or a write error has occurred, true otherwise.
static
bool
writeString(PRFileDesc *fd, const nsCString &str)
{
    PRInt32 res = PR_Write_Fully(fd, str.get(), str.Length());
    if (res < str.Length()) {
        return false;
    }
    return true;
}

void
nsHttpSlitheenConnector::
mainloop()
{
    nsresult rv = NS_ERROR_NOT_INITIALIZED;
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

        while(1) {
            nsCString str;
            bool ok = false;
            PR_RWLock_Rlock(mSocketLock);
            if (mChildSocket) {
                ok = readString(mChildSocket, str);
            }
            PR_RWLock_Unlock(mSocketLock);
            if (!ok) {
				std::cerr << "Error reading from socket. Closing.";
                PR_RWLock_Wlock(mSocketLock);
                if (mChildSocket) {
                    PR_Close(mChildSocket);
                    mChildSocket = nullptr;
                }
                PR_RWLock_Unlock(mSocketLock);
                break;
            }
            //TODO: Encrypt (and b64) received bytes
			if (smSlitheenSupercryptor == NULL ) {
				std::cerr << "Error: no supercryptor yet\n";
				break;
			}

			nsCString encodedBytes;
			std::cerr << "Encrypting " << str.Length() << "bytes:\n";
			for (int i=0; i< str.Length(); i++)
			std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) (str.get())[i] << " ";
			std::cerr << "\n";

			rv = smSlitheenSupercryptor->SlitheenEncrypt(str, str.Length(), encodedBytes);

			if (rv != NS_OK) {
				std::cerr << "Error encoding upstream bytes\n";
				continue;
			}

			std::cerr << "Sending upstream:\n";
			std::cerr << encodedBytes.get();
			std::cerr << "\n";

            PR_RWLock_Wlock(mUpstreamLock);
            mUpstreamQueue.push(encodedBytes);
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

    nsCString slitheenID;
    rv = supercryptor->SlitheenIDGet(slitheenID);

    if (rv != NS_OK) {
        std::cerr << "slitheen ID Get failed\n";
    }

    if (slitheenID.Length() > 0) {
        header.Assign("X-Slitheen: ");
        header.Append(slitheenID);
        //TODO: figure out a way to limit the size of appended chunks
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

    nsresult rv = NS_ERROR_NOT_INITIALIZED;
    std::cerr << "Slitheen resource received: (" << resource.Length() << " bytes)\n";

    //Decrypt data
    if (smSlitheenSupercryptor == NULL ) {
        return NS_ERROR_FAILURE;
    }

    nsCString decryptedData;
    PRUint32 datalen = 0;
    rv= smSlitheenSupercryptor->SlitheenDecrypt(resource, decryptedData, &datalen);

    if (rv != NS_OK) {
        std::cerr << "Slitheen decryption failed\n";
    }

	if (datalen == 0 ) {
        std::cerr << "No decrypted slitheen data available\n";
		return NS_OK;
	}

    std::cerr << "Got decrypted bytes";
    for (int i=0; i< datalen; i++)
	std::cerr << std::hex << std::setfill('0') << std::setw(2) << (int) (decryptedData.get())[i] << " ";
	std::cerr << "\n";

    // For now, just write the data to the socket, and assume the SOCKS
    // proxy is reading fast enough that this won't block (because we're
    // in the socket thread).
    bool ok = false;
    if (mChildSocket) {
        PR_RWLock_Rlock(mSocketLock);
        // mChildSocket may have changed by the time we get the lock
        if (mChildSocket) {
			std::cerr << "Writing " << datalen << " bytes to socks\n";
            ok = writeString(mChildSocket, decryptedData);
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
