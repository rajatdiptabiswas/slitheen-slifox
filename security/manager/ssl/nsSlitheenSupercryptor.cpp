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
    bool success = SSL_SlitheenSuperGen(); //TODO: do something with return
}

nsSlitheenSupercryptor::~nsSlitheenSupercryptor()
{
}

NS_IMPL_ISUPPORTS(nsSlitheenSupercryptor,
                  nsISlitheenSupercryptor)

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenIDGet(nsACString & id)
{
    unsigned char ids[SLITHEEN_ID_LEN];
    if (SECSuccess != SSL_SlitheenIDGet(ids)) {
        return NS_ERROR_FAILURE;
    }

    id.Assign((const char *)ids, SLITHEEN_ID_LEN);

    return NS_OK;
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenEncrypt(uint16_t streamid, const nsACString & data, uint32_t seq, uint32_t ack, uint16_t paddinglen, nsACString & encryptedblock)
{
    return NS_ERROR_FAILURE;
}

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenDecrypt(const nsACString & encryptedblock, uint32_t offset, uint16_t *streamid, nsACString & data, uint32_t *seq, uint32_t *ack, uint16_t *paddinglen, uint16_t *enclen)
{
    return NS_ERROR_FAILURE;
}
