#include <iostream>

#include "nsSlitheenConv.h"
#include "nsCOMPtr.h"
#include "nsError.h"
#include "nsStreamUtils.h"
#include "nsIRequest.h"

//namespace mozilla {
//namespace net {

const char *pixel =
    "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00\x25\xdb\x56\xca\x00\x00\x00\x03\x50\x4c\x54\x45\x00\xff\x00\x34\x5e\xc0\xa8\x00\x00\x00\x0a\x49\x44\x41\x54\x78\x9c\x63\x62\x00\x00\x00\x06\x00\x03\x36\x37\x7c\xa8\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

#define PIXEL_PNG_LEN 82

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

    uint32_t ret;
    char *buf = new char[aCount];
    if (!buf) {
        return NS_ERROR_OUT_OF_MEMORY;
    }

    nsresult rv = iStr->Read(buf, aCount, &ret);
    if (NS_FAILED(rv)) {
        return rv;
    }

    //replace data with 1x1 green pixel
    nsCOMPtr<nsIInputStream> replacementData;

    nsCString pixelData;
    pixelData.AssignLiteral(pixel, PIXEL_PNG_LEN);

    rv = NS_NewCStringInputStream(getter_AddRefs(replacementData), pixelData);
    if(NS_FAILED(rv)) {
        return rv;
    }

    std::cerr << "nsSlitheenConv::OnDataAvailable\n";
    return mListener->OnDataAvailable(request, aContext, replacementData, 0, PIXEL_PNG_LEN);

}

//} // namespace net
//} // namespace mozilla
