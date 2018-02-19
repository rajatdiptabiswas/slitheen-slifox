#if !defined(SlitheenConverter_h_)
#define SlitheenConverter_h_

namespace mozilla {

class SlitheenConverter final
{
public:
    SlitheenConverter();

    void Append(char *data, size_t len);
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
