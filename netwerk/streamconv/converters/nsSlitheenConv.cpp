#include <iostream>

#include "nsSlitheenConv.h"
#include "nsCOMPtr.h"
#include "nsError.h"
#include "nsStreamUtils.h"
#include "nsIRequest.h"

//namespace mozilla {
//namespace net {

// nsISupports implementation
NS_IMPL_ISUPPORTS(nsSlitheenConv,
                  nsIStreamConverter,
                  nsIStreamListener,
                  nsIRequestObserver)

nsSlitheenConv::nsSlitheenConv()
{
    std::cerr << "nsSlitheenConv ctor\n";
}

nsSlitheenConv::~nsSlitheenConv()
{
    std::cerr << "nsSlitheenConv dtor\n";
}

nsresult
nsSlitheenConv::Init()
{
    return NS_OK;
}

// nsIStreamConverter implementation

// No syncronous conversion at this time.
NS_IMETHODIMP
nsSlitheenConv::Convert(nsIInputStream *aFromStream,
                          const char *aFromType,
                          const char *aToType,
                          nsISupports *aCtxt, nsIInputStream **_retval) {
    return NS_ERROR_NOT_IMPLEMENTED;
}

// Stream converter service calls this to initialize the actual stream converter (us).
NS_IMETHODIMP
nsSlitheenConv::AsyncConvertData(const char *aFromType, const char *aToType,
                                   nsIStreamListener *aListener, nsISupports *aCtxt) {
    NS_ASSERTION(aListener && aFromType && aToType, "null pointer passed into multi mixed converter");

    // hook ourself up with the original listener that receives new data.
    mListener = aListener;

    return NS_OK;
}

//nsIStreamListener implementation

NS_IMETHODIMP
nsSlitheenConv::OnStartRequest(nsIRequest* request, nsISupports *aContext)
{

    std::cerr << "nsSlitheenConv::OnStartRequest\n";
    return mListener->OnStartRequest(request, aContext);
}


NS_IMETHODIMP
nsSlitheenConv::OnStopRequest(nsIRequest* request, nsISupports *aContext,
                                  nsresult aStatus)
{
    std::cerr << "nsSlitheenConv::OnStopRequest\n";
    return mListener->OnStopRequest(request, aContext, aStatus);
}


NS_IMETHODIMP
nsSlitheenConv::OnDataAvailable(nsIRequest* request,
                                    nsISupports *aContext,
                                    nsIInputStream *iStr,
                                    uint64_t aSourceOffset,
                                    uint32_t aCount)
{

    std::cerr << "nsSlitheenConv::OnDataAvailable\n";
    return mListener->OnDataAvailable(request, aContext, iStr, aSourceOffset, aCount);

}

//} // namespace net
//} // namespace mozilla
