/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsSlitheenSupercryptor.h"

#include "nsString.h"
#include "ssl.h"

nsSlitheenSupercryptor::nsSlitheenSupercryptor()
{
}

nsSlitheenSupercryptor::~nsSlitheenSupercryptor()
{
}

NS_IMPL_ISUPPORTS(nsSlitheenSupercryptor,
                  nsISlitheenSupercryptor)

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenIDGet(nsACString & id, bool *_retval)
{
    unsigned char ids[SLITHEEN_ID_LEN];
    bool ret = SSL_SlitheenIDGet(ids);
    if (ret) {
        id.Assign((const char *)ids, SLITHEEN_ID_LEN);
    }
    *_retval = ret;
    return NS_OK;
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenEncrypt(uint16_t streamid, const nsACString & data, uint32_t seq, uint32_t ack, uint16_t paddinglen, nsACString & encryptedblock, bool *_retval)
{
    *_retval = false;
    return NS_OK;
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenDecrypt(const nsACString & encryptedblock, uint32_t offset, uint16_t *streamid, nsACString & data, uint32_t *seq, uint32_t *ack, uint16_t *paddinglen, uint16_t *enclen, bool *_retval)
{
    *_retval = false;
    return NS_OK;
}
