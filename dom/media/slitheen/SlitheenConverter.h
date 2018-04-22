#if !defined(SlitheenConverter_h_)
#define SlitheenConverter_h_

#include "MediaInfo.h"

namespace mozilla {

class SlitheenConverter final
{
public:
    SlitheenConverter();

    void Append(char **data, size_t *len, int videoCodec, TrackInfo::TrackType aType, int isSlitheen);
    void Send();

    virtual ~SlitheenConverter();

private:
    nsCString mData;
    RefPtr<nsIThread> mSlitheenConverterThread;

    void InitializeThread();
    void Shutdown();

};
} //mozilla

#endif /*SlitheenConverter_h_ */
