/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsSlitheenSupercryptor.h"

#include "mozilla/Base64.h"
#include "nsString.h"
#include "ssl.h"

#include <iostream>

nsSlitheenSupercryptor::nsSlitheenSupercryptor()
{
}

nsSlitheenSupercryptor::~nsSlitheenSupercryptor()
{
}

NS_IMPL_ISUPPORTS(nsSlitheenSupercryptor,
                  nsISlitheenSupercryptor)

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenIDGet(nsACString & id)
{
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenEncrypt(const nsACString & data, uint16_t len, nsACString & encryptedblock)
{
	return mozilla::Base64Encode(data, encryptedblock);
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenDecrypt(const nsACString & encryptedblock, nsACString & data, uint32_t *len)
{
    const unsigned char *encryptedData = (const unsigned char *) encryptedblock.BeginReading();
    PRUint32 encryptedBodyLen;
    PRInt32 decryptedBodyLen;
    unsigned char *decryptedBody;
    unsigned char *decryptedHeader;


    PRUint32 remainingLength = encryptedblock.Length();

    return NS_OK;
}
