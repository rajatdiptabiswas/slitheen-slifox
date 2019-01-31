#ifndef nsHttpSlitheenConnector_h__
#define nsHttpSlitheenConnector_h__

#include "nsIURIContentListener.h"
#include "SlitheenConnectorChild.h"
#include "nsISlitheenSupercryptor.h"

#include <queue>

#include "prrwlock.h"
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

    //-------------------------------------------------------------------------
    // NOTE: functions below are called from any thread
    //-------------------------------------------------------------------------
    static nsHttpSlitheenConnector *getInstance() { return smConnector; }

    // If the Slitheen SOCKS proxy has already communicated the
    // SlitheenID to us, set header to "X-Slitheen: slitheenid ",
    // followed by all the upstream data chunks we have received (space
    // separated), followed by "\r\n" and return NS_OK.  Otherwise,
    // don't touch header and return NS_ERROR_NOT_INITIALIZED.
    nsresult getHeader(nsISlitheenSupercryptor *supercryptor, nsCString &header);

    // Attange to call this when there is a Slitheen downstream resource
    // available.
    nsresult OnSlitheenResource(const nsCString &resource);

    static void SendSlitheenResource(nsCString data);

    static nsresult ReceiveResource(nsCString resource);

private:
    virtual ~nsHttpSlitheenConnector();

    // There's only one Slitheen Connector; various classes have to talk
    // to it, so we keep a pointer to it in this static member.
    static nsHttpSlitheenConnector *smConnector;

    // A handle to the (single) SlitheenSupercryptor
    static nsISlitheenSupercryptor *smSlitheenSupercryptor;

    // Note about locks: if you grab more than one, grab them in this
    // order, and release them in the opposite order:
    // 1. mSocketLock
    // 2. mUpstreamLock

    nsCOMPtr<nsIURIContentListener> mContentListener;
                               // A wrapper pointer to the
                               // ContentListener object for handling
                               // downstream slitheen data

    PRThread *mThread;         // the Slitheen thread

    PRRWLock *mSocketLock;     // a lock protecting mChildSocket

    PRFileDesc *mSocket;       // the bound socket, being accept()ed on
    PRFileDesc *mChildSocket;  // the accepted socket; we only have one
                               //   active connection at a time

    PRRWLock *mUpstreamLock;   // a lock protecting mSlitheenID and
                               //   mUpstreamQueue

    nsCString mSlitheenID;     // the Slitheen ID, provided by the
                               //   Slitheen SOCKS proxy
    std::queue<nsCString> mUpstreamQueue;
                               // a queue of the upstream chunks,
                               //   provided by the Slitheen SOCKS proxy

    friend class nsAutoPtr<nsHttpSlitheenConnector>; // needs to call the destructor
};

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
    SlitheenConnectorChild *mConnectorChild;
};

} // namespace net
} // namespace mozilla

#endif // nsHttpSlitheenConnector_h__
