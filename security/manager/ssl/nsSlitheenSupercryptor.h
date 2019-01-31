/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef nsSlitheenSupercryptor_h
#define nsSlitheenSupercryptor_h

#include "nsISlitheenSupercryptor.h"

class nsSlitheenSupercryptor final : public nsISlitheenSupercryptor
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSISLITHEENSUPERCRYPTOR

  nsSlitheenSupercryptor();

protected:
  virtual ~nsSlitheenSupercryptor();

private:
};

#endif // nsSlitheenSupercryptor_h
