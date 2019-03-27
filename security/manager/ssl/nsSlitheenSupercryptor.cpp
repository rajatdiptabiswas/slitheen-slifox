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
    char ids[4*SLITHEEN_ID_LEN/3 + 4];
    if (SECSuccess != SSL_SlitheenIDGet(ids)) {
        return NS_ERROR_FAILURE;
    }

    id.Assign(ids);

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
    const unsigned char *encryptedData = (const unsigned char *) encryptedblock.BeginReading();
    PRUint32 encryptedBodyLen;
    unsigned char *decryptedBody;

    SSL_SlitheenHeader slitheenHeader;

    PRUint32 remainingLength = encryptedblock.Length();

    while (remainingLength > 0) {

        /* First decrypt the header so we know how long the encrypted body is */
        if (SECSuccess != SSL_SlitheenHeaderDecrypt(encryptedData, remainingLength,
                    &slitheenHeader, &encryptedBodyLen)) {
            return NS_ERROR_FAILURE;
        }

        remainingLength -= SLITHEEN_HEADER_LEN;
        encryptedData += SLITHEEN_HEADER_LEN;

        /* Now decrypt the body */
        if (slitheenHeader.datalen != 0 ) {


            if (encryptedBodyLen > remainingLength) {
                fprintf(stderr, "Error decrypting body: %d byte body with %d bytes remaining\n",
                        encryptedBodyLen, remainingLength);
                return NS_ERROR_FAILURE;
            }

            if (SECSuccess != SSL_SlitheenBodyDecrypt(encryptedData + SLITHEEN_HEADER_LEN,
                        encryptedBodyLen, &slitheenHeader, &decryptedBody)) {
                return NS_ERROR_FAILURE;
            }

            remainingLength -= encryptedBodyLen;
            encryptedData += encryptedBodyLen;

            data.Append((const char *) decryptedBody);
            PORT_Free(decryptedBody);
        }

        fprintf(stderr, "Received garbage bytes\n");
        
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
