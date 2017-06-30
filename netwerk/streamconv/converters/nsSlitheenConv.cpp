#include <iostream>

#include "nsSlitheenConv.h"
#include "nsCOMPtr.h"
#include "nsError.h"
#include "nsStreamUtils.h"
#include "nsIRequest.h"


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
nsSlitheenConv::OnStartRequest(nsIRequest* request)
{

    std::cerr << "nsSlitheenConv::OnStartRequest\n";
    return mListener->OnStartRequest(request);
}


NS_IMETHODIMP
nsSlitheenConv::OnStopRequest(nsIRequest* request, nsresult aStatus)
{
    std::cerr << "nsSlitheenConv::OnStopRequest\n";
    return mListener->OnStopRequest(request, aStatus);
}


NS_IMETHODIMP
nsSlitheenConv::OnDataAvailable(nsIRequest* request,
                                    nsIInputStream *iStr,
                                    uint64_t aSourceOffset,
                                    uint32_t aCount)
{

    std::cerr << "nsSlitheenConv::OnDataAvailable\n";
    return mListener->OnDataAvailable(request, iStr, aSourceOffset, aCount);

}

nsresult NS_NewSlitheenConv(nsSlitheenConv** aSlitheenConv) {
  MOZ_ASSERT(aSlitheenConv != nullptr, "null ptr");
  if (!aSlitheenConv) return NS_ERROR_NULL_POINTER;

  *aSlitheenConv = new nsSlitheenConv();

  NS_ADDREF(*aSlitheenConv);
  return NS_OK;
}
