#include <iostream>

#include "nsStreamUtils.h"
#include "prio.h"

#include "nsIStreamListener.h"
#include "nsIInputStream.h"
#include "mozilla/net/nsHttpSlitheenConnector.h"
#include "SlitheenConverter.h"

namespace mozilla {


SlitheenConverter::SlitheenConverter()
{
    InitializeThread();
}

SlitheenConverter::~SlitheenConverter()
{
    Shutdown();
}

void
SlitheenConverter::InitializeThread()
{
    MOZ_ASSERT(NS_IsMainThread());

}

void
SlitheenConverter::Shutdown()
{
    MOZ_ASSERT(NS_IsMainThread());

}

void
SlitheenConverter::Append(char *data, size_t length)
{
    mData.Append(data, length);
}

void
SlitheenConverter::Send()
{
    //Need to send this through the manager thread
    if(mData.Length() > 0) {
        net::nsHttpSlitheenConnector::ReceiveResource(mData);
    }
    mData.Assign("");
}

} //mozilla
