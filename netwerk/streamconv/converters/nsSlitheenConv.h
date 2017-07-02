#ifndef __nsslitheenconv__h__
#define __nsslitheenconv__h__

#include "nsIStreamConverter.h"
#include "nsCOMPtr.h"


//Note: this is a randomly-generated GUID
#define NS_NSSLITHEENCONVERTER_CID \
{ /*31F4F2B8-5DC4-11E7-9BEE98C77FA7C656 */ \
    0x31F4F2B8, \
    0x5DC4, \
    0x11E7, \
    {0x9B, 0xEE, 0x98, 0xC7, 0x7F, 0xA7, 0xC6, 0x56} \
}


class nsSlitheenConv : public nsIStreamConverter {
public:
    NS_DECL_ISUPPORTS
    NS_DECL_NSISTREAMCONVERTER
    NS_DECL_NSISTREAMLISTENER
    NS_DECL_NSIREQUESTOBSERVER

    nsSlitheenConv();
    nsresult Init();

protected:
    virtual ~nsSlitheenConv();

    nsCOMPtr<nsIStreamListener> mListener; // the original listener to which "converted" data is sent

    nsCOMPtr<nsIStreamListener> mSlitheenListener;

};
#endif /* __nsslitheenconv__h__ */
