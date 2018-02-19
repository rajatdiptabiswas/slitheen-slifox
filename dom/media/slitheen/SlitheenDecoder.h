/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#if !defined(SlitheenDecoder_h_)
#define SlitheenDecoder_h_

#include "MediaDecoder.h"
#include "MediaFormatReader.h"

namespace mozilla {

class SlitheenDecoder : public MediaDecoder
{
public:
  explicit SlitheenDecoder(MediaDecoderOwner* aOwner) : MediaDecoder(aOwner) {}
  MediaDecoder* Clone(MediaDecoderOwner* aOwner) override {
    //if (!IsSlitheenEnabled()) {
    //  return nullptr;
    //}
    return new SlitheenDecoder(aOwner);
  }
  MediaDecoderStateMachine* CreateStateMachine() override;

  // Returns true always for now
  static bool IsEnabled();

  // Returns true if aMIMEType is a Slitheen replaced content type
  static bool CanHandleMediaType(const nsACString& aMIMETypeExcludingCodecs,
                                 const nsAString& aCodecs);

  static bool CanHandleMediaType(const nsAString& aContentType);

  // Returns true if aData starts with a Slitheen segment.
  // If a Slitheen header is present, this method will replace the header value
  // with a valid Cluster header.
  // Return NS_OK if segment is present, NS_ERROR_NOT_AVAILABLE if insufficient
  // data is currently available to make a determination. Any other value
  // indicates an error.
  static MediaResult IsSlitheenSegmentPresent(MediaByteBuffer* aData);

  void GetMozDebugReaderData(nsAString& aString) override;

private:
  RefPtr<MediaFormatReader> mReader;
};

} // namespace mozilla

#endif
