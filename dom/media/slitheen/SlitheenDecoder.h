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

class MediaContainerType;

class SlitheenDecoder
{
public:

  // Returns true if aContainerType is a WebM type that we think we can render
  // with an enabled platform decoder backend.
  // If provided, codecs are checked for support.
  static bool IsSupportedType(const MediaContainerType& aContainerType);


  // Returns true if aData starts with a Slitheen segment.
  // If a Slitheen header is present, this method will replace the header value
  // with a valid Cluster header.
  // Return NS_OK if segment is present, NS_ERROR_NOT_AVAILABLE if insufficient
  // data is currently available to make a determination. Any other value
  // indicates an error.
  static MediaResult IsSlitheenSegmentPresent(MediaByteBuffer* aData);

};

} // namespace mozilla

#endif
