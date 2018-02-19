/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>

#include "mozilla/Preferences.h"
#include "MediaDecoderStateMachine.h"
#include "WebMDemuxer.h"
#include "SlitheenDecoder.h"
#include "VideoUtils.h"
#include "nsContentTypeParser.h"

namespace mozilla {

MediaDecoderStateMachine* SlitheenDecoder::CreateStateMachine()
{
  mReader =
    new MediaFormatReader(this, new WebMDemuxer(GetResource()), GetVideoFrameContainer());
  return new MediaDecoderStateMachine(this, mReader);
}

/* static */
bool
SlitheenDecoder::IsEnabled()
{
  return true; //For now just return true, look up how to add this to preferences later
  //return Preferences::GetBool("media.webm.enabled");
}

/* static */
bool
SlitheenDecoder::CanHandleMediaType(const nsACString& aMIMETypeExcludingCodecs,
                                const nsAString& aCodecs)
{
  if (!IsEnabled()) {
    return false;
  }

  //std::cerr << "In SlitheenDecoder::CanHandleMediaType\n";
  //std::cerr << "MIMEType: " << aMIMETypeExcludingCodecs.BeginReading() << "\n";

  const bool isSlitheenAudio = aMIMETypeExcludingCodecs.EqualsASCII("sli/theena");
  const bool isSlitheenVideo = aMIMETypeExcludingCodecs.EqualsASCII("sli/theenv");
  if (!isSlitheenAudio && !isSlitheenVideo) {
    return false;
  }

  return true;
}

/* static */ bool
SlitheenDecoder::CanHandleMediaType(const nsAString& aContentType)
{
  nsContentTypeParser parser(aContentType);
  nsAutoString mimeType;
  nsresult rv = parser.GetType(mimeType);
  if (NS_FAILED(rv)) {
    return false;
  }

  //std::cerr << "SlitheenDecoder::CanHandleMediaType (static?)\n";
  //std::cerr << "Content Type: " << mimeType.get() << "\n";
  nsString codecs;
  parser.GetParameter("codecs", codecs);

  return CanHandleMediaType(NS_ConvertUTF16toUTF8(mimeType),
                            codecs);
}

void
SlitheenDecoder::GetMozDebugReaderData(nsAString& aString)
{
  if (mReader) {
    mReader->GetMozDebugReaderData(aString);
  }
}

/* static */
MediaResult
SlitheenDecoder::IsSlitheenSegmentPresent(MediaByteBuffer* aData)
{

  std::cerr << "In SlitheenDecoder::IsSlitheenSegmentPresent\n";
  if (aData->Length() < 4) {
    return NS_ERROR_NOT_AVAILABLE;
  }

  // 0x16736c69 //Slitheen
  if ((*aData)[0] == 0x16 && (*aData)[1] == 0x73 && (*aData)[2] == 0x6c &&
      (*aData)[3] == 0x69) {

    //change header to Cluster header
    (*aData)[0] = 0x1f;
    (*aData)[1] = 0x43;
    (*aData)[2] = 0xb6;
    (*aData)[3] = 0x75;

    std::cerr << "Found Slitheen segment!\n";
    return NS_OK;
  }

  return MediaResult(NS_ERROR_FAILURE, RESULT_DETAIL("Invalid webm content"));
}

} // namespace mozilla

