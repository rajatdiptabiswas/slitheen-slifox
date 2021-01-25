#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <base64.h>
#include "prerror.h"
#include "prio.h"
#include "ssl.h"
#include "sslimpl.h"
#include "pk11func.h"
#include "slitheen.h"

typedef struct {
    byte maingen[PTWIST_BYTES];
    byte twistgen[PTWIST_BYTES];
    byte mainpub[PTWIST_BYTES];
    byte twistpub[PTWIST_BYTES];
} SlitheenKeys;

#define AES_CBC_KEYLEN 32

static char* slitheenID;
static PK11SymKey *super_body_key;
static PK11SymKey *super_header_key;
static PK11SymKey *super_mac_key;

/*
 * Load the current Slitheen public keys into the SlitheenKeys struct.
 * Returns 0 on success, -1 on failure.
 */

#ifdef SLITHEEN_TAG_TESTING

int main(int argc, char **argv)
{
//    return 0;
}

#endif  /* SLITHEEN_TAG_TESTING */

/* Initialize super encryption contexts */
PK11Context *superCipherInit(PK11SymKey *pk11key, CK_MECHANISM_TYPE type, const PRUint8 *iv,
        unsigned int ivlen, CK_ATTRIBUTE_TYPE operation)
{
    SECItem secItem;
    secItem.data = iv;
    secItem.len = ivlen;
    PK11Context *ctx = NULL;

    ctx = PK11_CreateContextBySymKey(type, operation, pk11key, &secItem);

    return ctx;
}

/* Common encryption/decryption function */
SECStatus superCipher(PK11Context *ctx, PRUint8 *out, PRInt32 *outlen,
        unsigned int maxout, const PRUint8 *in, unsigned int len)
{
    if (SECSuccess != PK11_CipherOp(ctx, out, outlen, maxout, in, len)) {
        return SECFailure;
    }

    return SECSuccess;
}

/* Encrypt some covert data.  Pass in the header and the body.
 * *encryptedblockp will be set to a newly allocated block, which will
 * be owned by the caller and must be freed with PORT_Free. *enclenp
 * will be set to the length of the encrypted block. */
SSL_IMPORT SECStatus SSL_SlitheenEncrypt(const PRUint32 len,
    const PRUint8 *body, char **encodedbody)
{
	//Right now this just b64 encodes the data
    *encodedbody = BTOA_DataToAscii(body, len); //Should be freed later with PORT_Free
	
    return SECSuccess;
}

/* Decrypt the Slitheen body of some covert data.  Pass in the
 * encrypted body and its length, as well as a pointer to a
 * the SSL_SlitheenHeader struct filled in by SSL_SlitheenHeaderDecrypt.
 * *bodyp will be set to a newly allocated block, which will be owned by
 * the caller and must be freed with PORT_Free. */
SSL_IMPORT SECStatus SSL_SlitheenBodyDecrypt(const PRUint8 *encryptedbody,
    PRUint32 encbodylen, const SSL_SlitheenHeader *header, PRUint8 **bodyp, PRInt32 *decbodylenp)
{
    PK11Context *ctx = superCipherInit(super_body_key, CKM_AES_CBC, encryptedbody, 16, CKA_DECRYPT);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize cbc context\n");
        return SECFailure;
    }

    PRUint32 len = encbodylen;
    if(len %16){ //add padding to len
        len += 16 - len%16;
    }

    fprintf(stderr, "Encrypted slitheen body (%d bytes):", encbodylen);
    for (PRUint32 i=0; i< encbodylen; i++){
        fprintf(stderr, "%02x ", encryptedbody[i]);
    }
    fprintf(stderr, "\n");

    PRUint8 *decryptedbody = PORT_Alloc(len);
    if (SECSuccess != superCipher(ctx, decryptedbody, decbodylenp, len, encryptedbody+16, len)) {
        PORT_Free(decryptedbody);
        return SECFailure; //TODO: return what previous function returned
    }

    fprintf(stderr, "Decrypted slitheen body (%d bytes):", *decbodylenp);
    for (PRInt32 i=0; i< *decbodylenp; i++){
        fprintf(stderr, "%02x ", decryptedbody[i]);
    }
    fprintf(stderr, "\n");

    *bodyp = decryptedbody;

    return SECSuccess;
}
