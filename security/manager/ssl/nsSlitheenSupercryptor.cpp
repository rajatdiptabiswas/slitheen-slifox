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
    SSL_SlitheenSuperGen(); //TODO: do something with return
}

nsSlitheenSupercryptor::~nsSlitheenSupercryptor()
{
}

NS_IMPL_ISUPPORTS(nsSlitheenSupercryptor,
                  nsISlitheenSupercryptor)

NS_IMETHODIMP
nsSlitheenSupercryptor::SlitheenIDGet(nsACString & id)
{
    char ids[4*SLITHEEN_ID_LEN/3 + 4];
    if (SECSuccess != SSL_SlitheenIDGet(ids)) {
        return NS_ERROR_FAILURE;
    }

    id.Assign(ids);

    return NS_OK;
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

    SSL_SlitheenHeader slitheenHeader;

    PRUint32 remainingLength = encryptedblock.Length();

    while (remainingLength > 0) {

        /* First decrypt the header so we know how long the encrypted body is */
        if (SECSuccess != SSL_SlitheenHeaderDecrypt(encryptedData, remainingLength,
                    &slitheenHeader, &decryptedHeader, &encryptedBodyLen)) {
            return NS_ERROR_FAILURE;
        }

        remainingLength -= SLITHEEN_HEADER_LEN;
        encryptedData += SLITHEEN_HEADER_LEN;


        if (slitheenHeader.datalen != 0 ) {
			data.Append((const char *) decryptedHeader, SLITHEEN_HEADER_LEN - 4);
			*len += SLITHEEN_HEADER_LEN - 4;
		}
		PORT_Free(decryptedHeader);

        /* Now decrypt the body */
        if (slitheenHeader.datalen != 0 ) {


            if (encryptedBodyLen > remainingLength) {
                fprintf(stderr, "Error decrypting body: %d byte body with %d bytes remaining\n",
                        encryptedBodyLen, remainingLength);
                return NS_ERROR_FAILURE;
            }

            if (SECSuccess != SSL_SlitheenBodyDecrypt(encryptedData,
                        encryptedBodyLen, &slitheenHeader, &decryptedBody, &decryptedBodyLen)) {
                return NS_ERROR_FAILURE;
            }

            remainingLength -= decryptedBodyLen + 32;
            encryptedData += decryptedBodyLen + 32;

            data.Append((const char *) decryptedBody, (PRUint32) slitheenHeader.datalen);
			*len += slitheenHeader.datalen;
            PORT_Free(decryptedBody);
        }

        if (slitheenHeader.paddinglen > remainingLength ) {
            fprintf(stderr, "Error: %d byte padding with %d bytes remaining\n",
                    slitheenHeader.paddinglen, remainingLength);
            return NS_ERROR_FAILURE;
        }

        remainingLength -= slitheenHeader.paddinglen;
        encryptedData += slitheenHeader.paddinglen;

        fprintf(stderr, "Remaining encrypted bytes: %d\n", remainingLength);

    }

    return NS_OK;
}
