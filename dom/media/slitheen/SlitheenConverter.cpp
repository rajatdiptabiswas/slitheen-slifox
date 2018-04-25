#include <iostream>

#include "nsStreamUtils.h"
#include "prio.h"

#include "nsIStreamListener.h"
#include "nsIInputStream.h"
#include "mozilla/net/nsHttpSlitheenConnector.h"
#include "MediaInfo.h"
#include "SlitheenConverter.h"
#include "NesteggPacketHolder.h"

static const char *dummyFrame =
    "\x82\x49\x83\x42\x00\x27\xf0\x1d\xf6\x00\x38\x24\x1c\x18\x28"
    "\x10\x00\x58\x61\xf6\x3f\xe3\xb2\x68\x05\xcd\x1e\xe0\x00\x00"
    "\x00\x00\x13\x13\x5b\xfa\x7b\x52\x75\xbc\x74\xf1\xa3\xc3\x8e"
    "\x9e\x34\x8e\x59\xe8\x99\x00\x13\x5b\xfa\x7b\x52\x75\xbc\x74"
    "\xf1\xa3\xc3\x8e\x9e\x34\x8e\x59\xe8\x99\x00";

#define DUMMY_KEYFRAME_LENGTH 71

static const char *dummyAudio ="\xfc";

#define DUMMY_AUDIO_LENGTH 1

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
SlitheenConverter::Append(char **data, size_t *length, int codec, TrackInfo::TrackType aType, int isSlitheen)
{
    if (isSlitheen) {
        mData.Append(*data, *length);
    }

    char *dummyData = (char *) malloc(DUMMY_KEYFRAME_LENGTH);
    //Now replace with dummy keyframe

    if (aType == TrackInfo::kAudioTrack) {
        if (codec == NESTEGG_CODEC_VORBIS) {
            std::cerr << "Error: vorbis\n";
            memcpy(dummyData, dummyAudio, DUMMY_AUDIO_LENGTH);

            *length = DUMMY_AUDIO_LENGTH;
            *data = dummyData;

        } else if (codec == NESTEGG_CODEC_OPUS) {
            memcpy(dummyData, dummyAudio, DUMMY_AUDIO_LENGTH);

            *length = DUMMY_AUDIO_LENGTH;
            *data = dummyData;
        } else {
            std::cerr << "Unknown video codec\n";
        }

    } else if (aType == TrackInfo::kVideoTrack ) {
        if (codec == NESTEGG_CODEC_VP9) {

            memcpy(dummyData, dummyFrame, DUMMY_KEYFRAME_LENGTH);

            *length = DUMMY_KEYFRAME_LENGTH;
            *data = dummyData;
        } else if (codec == NESTEGG_CODEC_VP8) {
            memcpy(dummyData, dummyFrame, DUMMY_KEYFRAME_LENGTH);

            *length = DUMMY_KEYFRAME_LENGTH;
            *data = dummyData;
            std::cerr << "Error: VP8\n";
        } else {
            std::cerr << "Unknown video codec\n";
        }
    }
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
