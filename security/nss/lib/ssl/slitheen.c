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
static int slitheen_load_current_keys(SlitheenKeys *slitheenkeys)
{
    const char *pubkeyfilename;
    FILE *pubkeyf;
    int res;

    /* Create the generators */
    memset(slitheenkeys->maingen, 0, PTWIST_BYTES);
    slitheenkeys->maingen[0] = 2;
    memset(slitheenkeys->twistgen, 0, PTWIST_BYTES);

    /* Find the Slitheen pubkey file */
    pubkeyfilename = PR_GetEnvSecure("SLITHEEN_PUBKEY");
    if (pubkeyfilename == NULL || *pubkeyfilename == '\0') {
        fprintf(stderr, "SLITHEEN_PUBKEY undefined\n");
        return -1;
    }

    pubkeyf = fopen(pubkeyfilename, "rb");
    if (pubkeyf == NULL) {
        perror("fopen slitheen pubkey file");
        return -1;
    }
    res = fread(slitheenkeys->mainpub, PTWIST_BYTES, 1, pubkeyf);
    if (res < 1) {
        perror("fread slitheen pubkey file");
        return -1;
    }
    res = fread(slitheenkeys->twistpub, PTWIST_BYTES, 1, pubkeyf);
    if (res < 1) {
        perror("fread slitheen pubkey file");
        return -1;
    }
    fclose(pubkeyf);

    return 0;
}

static void slitheen_gen_tag(byte tag[PTWIST_TAG_BYTES], byte key[16],
        const byte *context, size_t context_len,
        const byte randbytes[PTWIST_RANDBYTES],
        const SlitheenKeys *slitheenkeys)
{
    byte seckey[PTWIST_BYTES];
    byte sharedsec[PTWIST_BYTES+context_len];
    byte usetwist;
    byte taghashout[32];
#if PTWIST_PUZZLE_STRENGTH > 0
    size_t puzzle_len = 16+PTWIST_RESP_BYTES;
    byte value_to_hash[puzzle_len];
    byte hashout[32];
    bn_t Rbn, Hbn;
    int i, len, sign;
#endif

    memset(tag, 0xAA, PTWIST_TAG_BYTES);

    /* Use the main or the twist curve? */
    usetwist = randbytes[0] & 0x01;

    /* Create seckey*G and seckey*Y */
    memmove(seckey, randbytes+1, PTWIST_BYTES);
    ptwist_pointmul(tag, usetwist ?
                        slitheenkeys->twistgen : slitheenkeys->maingen,
                        seckey);
    ptwist_pointmul(sharedsec, usetwist ?
                        slitheenkeys->twistpub : slitheenkeys->mainpub,
                        seckey);

    /* Create the tag hash keys */
    memmove(sharedsec+PTWIST_BYTES, context, context_len);
    PK11_HashBuf(SEC_OID_SHA256, taghashout, sharedsec,
                        PTWIST_BYTES+context_len);

#if PTWIST_PUZZLE_STRENGTH > 0
    #error "Tag puzzle not currently supported."

    /* The puzzle is to find a response R such that SHA256(K || R)
       starts with PTWIST_PUZZLE_STRENGTH bits of 0s.  K is the first
       128 bits of the above hash tag keys. */

    /* Construct our response to the puzzle.  Start looking for R in a
     * random place. */
    memmove(value_to_hash, taghashout, 16);
    RAND_bytes(value_to_hash+16, PTWIST_RESP_BYTES);
    value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;

    while(1) {
        unsigned int firstbits;

        md_map_sh256(hashout, value_to_hash, puzzle_len);
#if PTWIST_PUZZLE_STRENGTH < 32
        /* This assumes that you're on an architecture that doesn't care
         * about alignment, and is little endian. */
        firstbits = *(unsigned int*)hashout;
        if ((firstbits & PTWIST_PUZZLE_MASK) == 0) {
            break;
        }
        /* Increment R and try again. */
        for(i=0;i<PTWIST_RESP_BYTES;++i) {
            if (++value_to_hash[16+i]) break;
        }
        value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;
#else
#error "Code assumes PTWIST_PUZZLE_STRENGTH < 32"
#endif
    }

        /*
        for(i=0;i<puzzle_len;++i) {
            printf("%02x", value_to_hash[i]);
            if ((i%4) == 3) printf(" ");
        }
        printf("\n");
        for(i=0;i<32;++i) {
            printf("%02x", hashout[i]);
            if ((i%4) == 3) printf(" ");
        }
        printf("\n");
        */
    /* When we get here, we have solved the puzzle.  R is in
     * value_to_hash[16..16+PTWIST_RESP_BYTES-1], the hash output
     * hashout starts with PTWIST_PUZZLE_STRENGTH bits of 0s, and we'll
     * want to copy out H (the next PTWIST_HASH_SHOWBITS bits of the
     * hash output).  The final tag is [seckey*G]_x || R || H . */
    bn_new(Rbn);
    bn_new(Hbn);

    bn_read_bin(Rbn, value_to_hash+16, PTWIST_RESP_BYTES, BN_POS);
    hashout[PTWIST_HASH_TOTBYTES-1] &= PTWIST_HASH_MASK;
    bn_read_bin(Hbn, hashout, PTWIST_HASH_TOTBYTES, BN_POS);
    bn_lsh(Hbn, Hbn, PTWIST_RESP_BITS-PTWIST_PUZZLE_STRENGTH);
    bn_add(Hbn, Hbn, Rbn);
    len = PTWIST_TAG_BYTES-PTWIST_BYTES;
    bn_write_bin(tag+PTWIST_BYTES, &len, &sign, Hbn);
        /*
        for(i=0;i<PTWIST_TAG_BYTES;++i) {
            printf("%02x", tag[i]);
            if ((i%4) == 3) printf(" ");
        }
        printf("\n");
        */

    bn_free(Rbn);
    bn_free(Hbn);
#elif PTWIST_HASH_SHOWBITS <= 128
    /* We're not using a client puzzle, so the tag is [seckey*G]_x || H
     * where H is the first PTWIST_HASH_SHOWBITS bits of the above hash
     * output.  The key generated is the last 128 bits of that output.
     * If there's no client puzzle, PTWIST_HASH_SHOWBITS must be a multiple
     * of 8. */
    memmove(tag+PTWIST_BYTES, taghashout, PTWIST_HASH_SHOWBITS/8);
#else
#error "No client puzzle used, but PWTIST_HASH_SHOWBITS > 128"
#endif

    memmove(key, taghashout+16, 16);
}

static SECStatus SlitheenClientRandomCallback(sslSocket *ss, SSL3Random r)
{
    SlitheenKeys skeys;
    int res;
    size_t offset = SSL3_RANDOM_LENGTH - PTWIST_TAG_BYTES;
    byte randbytes[PTWIST_RANDBYTES];
    unsigned char context[4 + SSL3_RANDOM_LENGTH - PTWIST_TAG_BYTES];
    PRNetAddr peeraddr;
    PRStatus prres;
    PRUint8 *p;

    p = r;

    PORT_Assert(SSL3_RANDOM_LENGTH >= PWTIST_TAG_BYTES);

    prres = PR_GetPeerName(ss->fd, &peeraddr);
    if (prres == PR_SUCCESS) {
        if (peeraddr.inet.family != PR_AF_INET) {
            fprintf(stderr, "Unexpected address family: %d\n",
                    peeraddr.inet.family);
            return SECFailure;
        } else {
            /*
            fprintf(stderr, "Connected to %08x:%d\n", ntohl(peeraddr.inet.ip),
                ntohs(peeraddr.inet.port));
            */
            PORT_Memcpy(context, &peeraddr.inet.ip, 4);
        }
    } else {
        fprintf(stderr, "GetPeerName failed: %d\n", PR_GetError());
        return SECFailure;
    }

    res = slitheen_load_current_keys(&skeys);
    if (res < 0) {
        ss->slitheenState = SSLSlitheenStateOff;
        return SECFailure;
    }

    /* Generate random bytes to feed into the tag generator */
    PK11_GenerateRandom(randbytes, PTWIST_RANDBYTES);

    /* Genreate random bytes to put in front of the tag */
    if (offset > 0) {
        PK11_GenerateRandom(r, offset);
        PORT_Memcpy(context + 4, r, offset);
    }

    slitheen_gen_tag(p+offset, ss->slitheenSharedSecret,
        context, sizeof(context), randbytes, &skeys);
    memmove(ss->slitheenRouterPubkey, skeys.mainpub,
        sizeof(ss->slitheenRouterPubkey));
    ss->slitheenState = SSLSlitheenStateTagged;

    return SECSuccess;
}

#ifdef SLITHEEN_TAG_TESTING

int main(int argc, char **argv)
{
    FILE *fp;
    int res;
    int i;
    byte tag[PTWIST_TAG_BYTES];
    int numtags = argc > 1 ? atoi(argv[1]) : 10;

    /* Create the generators */
    memset(maingen, 0, PTWIST_BYTES);
    maingen[0] = 2;
    memset(twistgen, 0, PTWIST_BYTES);

    /* Read the public keys */
    fp = fopen("pubkey", "rb");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    res = fread(mainpub, PTWIST_BYTES, 1, fp);
    if (res < 1) {
        perror("fread");
        exit(1);
    }
    res = fread(twistpub, PTWIST_BYTES, 1, fp);
    if (res < 1) {
        perror("fread");
        exit(1);
    }
    fclose(fp);

    fp = fopen("tags", "wb");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    for(i=0;i<numtags;++i) {
        byte key[16];
#if 0
        int j;
#endif
        gen_tag(tag, key, (const byte *)"context", 7);
        fwrite(tag, PTWIST_TAG_BYTES, 1, fp);
#if 0
        for(j=0;j<16;++j) {
            printf("%02x", key[j]);
        }
        printf("\n");
#endif
    }
    fclose(fp);

    return 0;
}

#endif  /* SLITHEEN_TAG_TESTING */

static SECStatus SlitheenGenECDHEKeyCallback(const sslSocket *ss,
        unsigned int group_bits, SECKEYECParams *ecParams,
        SECKEYPublicKey **pubKey, SECKEYPrivateKey **privKey)
{
    SECItem keysecitem;
    SECItem prfparam = { siBuffer, NULL, 0 };
    PK11SymKey *pk11symkey = NULL;
    PK11Context *prf_context = NULL;
    SECStatus rv = SECFailure;
    unsigned int retlen = 0;
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    int privkeylen = 0;
    CK_BYTE *privkeybytes = NULL;

    if (slot == NULL) {
        return SECFailure;
    }

    if (ss == NULL || ecParams == NULL || pubKey == NULL || privKey == NULL) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    if (ss->slitheenState != SSLSlitheenStateTagged) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    *privKey = NULL;
    *pubKey = NULL;

    privkeylen = (group_bits+7)/8;
    if (privkeylen < 10) {
        /* Unreasonably small key */
        PK11_FreeSlot(slot);
        return SECFailure;
    }
    privkeybytes = PORT_Alloc(privkeylen);
    if (!privkeybytes) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    /* Create a MAC key PKCS11 object out of the client-relay shared
     * secret */
    keysecitem.type = siBuffer;
    keysecitem.data = (unsigned char *)(ss->slitheenSharedSecret);
    keysecitem.len = SLITHEEN_SS_LEN;

    pk11symkey = PK11_ImportSymKey(slot, CKM_SHA256_HMAC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        PORT_ZFree(privkeybytes, privkeylen);
        return SECFailure;
    }

    PRINT_KEY(0,(ss, "Slitheen Shared Secret:", pk11symkey));

    /* The ECDH private key will be PRF_pk11symkey("SLITHEEN_KEYGEN") */

    prf_context = PK11_CreateContextBySymKey(
                    CKM_NSS_TLS_PRF_GENERAL_SHA256, CKA_SIGN,
                    pk11symkey, &prfparam);
    if (!prf_context) {
        PK11_FreeSymKey(pk11symkey);
        PORT_ZFree(privkeybytes, privkeylen);
        return SECFailure;
    }

    rv = PK11_DigestBegin(prf_context);
    rv |= PK11_DigestOp(prf_context,
                        (const unsigned char *)"SLITHEEN_KEYGEN", 15);
    rv |= PK11_DigestFinal(prf_context, privkeybytes, &retlen,
                            privkeylen);

    PK11_DestroyContext(prf_context, PR_TRUE);
    prf_context = NULL;
    SECITEM_FreeItem(&prfparam, PR_FALSE);
    PK11_FreeSymKey(pk11symkey);
    pk11symkey = NULL;

    /* We have already checked that privkeylen (which is an int) is at
     * least 10, so casting it to unsigned int is safe. */
    if (rv != SECSuccess || retlen != (unsigned int)privkeylen) {
        PORT_ZFree(privkeybytes, privkeylen);
        return SECFailure;
    }

    /* Generate the key */

    *privKey = SECKEY_CreateECPrivateKeyPrivBytes(ecParams, pubKey,
                                            ss->pkcs11PinArg,
                                            privkeybytes, privkeylen);
    PORT_ZFree(privkeybytes, privkeylen);
    if (*privKey == NULL) {
        return SECFailure;
    }

    return SECSuccess;
}

static SECStatus SlitheenFinishedMACCallback(sslSocket *ss,
    const TLSFinished* finmsg, const TLSFinished *expectedfinmsg)
{
    SECItem keysecitem;
    SECItem macparam = { siBuffer, NULL, 0 };
    PK11SymKey *pk11symkey = NULL;
    PK11Context *mac_context = NULL;
    SECStatus rv = SECFailure;
    unsigned int retlen = 0;
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    PRUint8 MACdmessage[12];
    int orig_match = 0, macd_match = 0;

    if (slot == NULL) {
        return SECFailure;
    }

    if (ss == NULL || finmsg == NULL || expectedfinmsg == NULL ||
            sizeof(TLSFinished) != 12) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    if (ss->slitheenState != SSLSlitheenStateTagged &&
            ss->slitheenState != SSLSlitheenStateNack &&
            ss->slitheenState != SSLSlitheenStateAcknowledged) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    /* Create a MAC key PKCS11 object out of the client-relay shared
     * secret */
    keysecitem.type = siBuffer;
    keysecitem.data = ss->slitheenSharedSecret;
    keysecitem.len = SLITHEEN_SS_LEN;

    pk11symkey = PK11_ImportSymKey(slot, CKM_SHA256_HMAC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        return SECFailure;
    }

    mac_context = PK11_CreateContextBySymKey(
                    CKM_SHA256_HMAC, CKA_SIGN,
                    pk11symkey, &macparam);
    if (!mac_context) {
        PK11_FreeSymKey(pk11symkey);
        return SECFailure;
    }

    rv = PK11_DigestBegin(mac_context);
    rv |= PK11_DigestOp(mac_context,
                        (const unsigned char *)"SLITHEEN_FINISHED", 17);
    rv |= PK11_DigestOp(mac_context,
                        (const unsigned char *)expectedfinmsg, 12);
    rv |= PK11_DigestFinal(mac_context, MACdmessage, &retlen, 12);

    PK11_DestroyContext(mac_context, PR_TRUE);
    mac_context = NULL;
    SECITEM_FreeItem(&macparam, PR_FALSE);
    PK11_FreeSymKey(pk11symkey);
    pk11symkey = NULL;

    if (rv != SECSuccess || retlen != 12) {
        return SECFailure;
    }

    PRINT_BUF(0,(ss,"Slitheen state:", &(ss->slitheenState), sizeof(ss->slitheenState)));
    PRINT_BUF(0,(ss,"Received Finish:", finmsg, sizeof(TLSFinished)));
    PRINT_BUF(0,(ss,"Expected Finish:", expectedfinmsg, sizeof(TLSFinished)));
    PRINT_BUF(0,(ss,"Slitheen Finish:", MACdmessage, sizeof(TLSFinished)));

    orig_match = !NSS_SecureMemcmp(finmsg, expectedfinmsg,
                                    sizeof(TLSFinished));
    macd_match = !NSS_SecureMemcmp(finmsg, MACdmessage,
                                    sizeof(TLSFinished));

    ss->slitheenState = macd_match ? SSLSlitheenStateAcknowledged :
                                        SSLSlitheenStateNack;

#ifdef TRACE
    if (ss->slitheenState == SSLSlitheenStateAcknowledged) {
        fprintf(stderr, "Slitheen acknowledged on socket %p\n", ss);
        SSL_TRC(0,("\nSlitheen acknowledged on socket %p\n", ss));
    }
    /*
    if (ss->slitheenState == SSLSlitheenStateNack) {
        SSL_TRC(0,("\nSlitheen not acknowledged on socket %p\n", ss));
    }
    */
#endif

    if (orig_match || macd_match) {
        return SECSuccess;
    }

    return SECFailure;
}

SECStatus SlitheenEnable(sslSocket *ss, PRBool on)
{
    if (on) {
        ss->clientRandomCallback = SlitheenClientRandomCallback;
        ss->generateECDHEKeyCallback = SlitheenGenECDHEKeyCallback;
        ss->finishedMACCallback = SlitheenFinishedMACCallback;
        ss->slitheenState = SSLSlitheenStateNotStarted;
    } else {
        ss->clientRandomCallback = NULL;
        ss->generateECDHEKeyCallback = NULL;
        ss->finishedMACCallback = NULL;
        ss->slitheenState = SSLSlitheenStateOff;
    }

    return SECSuccess;
}

PRBool SlitheenEnabled(const sslSocket *ss)
{
    return (ss->slitheenState != SSLSlitheenStateOff);
}


PRBool SlitheenCompleted(const sslSocket *ss)
{
    return (ss->slitheenState == SSLSlitheenStateAcknowledged ||
        ss->slitheenState == SSLSlitheenStateNack);
}

PRBool SlitheenUsable(const sslSocket *ss)
{
    return (ss->slitheenState == SSLSlitheenStateAcknowledged);
}

/* Called once per slitheen client. Generates the SlitheenID and
 * the supercryption keys */
SSL_IMPORT SECStatus SSL_SlitheenSuperGen()
{
    SECStatus rv;
    SlitheenKeys skeys;
    SECItem keysecitem;
    PK11Context *prf_context = NULL;
    unsigned int retlen = 0;
    static PRUint8 clientID[SLITHEEN_ID_LEN];

    /* Load slitheen pub key */
    int res = slitheen_load_current_keys(&skeys);
    if (res < 0) {
        return SECFailure;
    }

    /* Generate the slitheenID */
    PRUint8 secret[SLITHEEN_SS_LEN];
    byte randbytes[PTWIST_RANDBYTES];
    PK11_GenerateRandom(randbytes, PTWIST_RANDBYTES);

    slitheen_gen_tag(clientID, secret,
        (const byte *)"context", 7, randbytes, &skeys);

    fprintf(stdout, "Generated slitheen ID:");
    for (int i=0; i< SLITHEEN_ID_LEN; i++) {
        fprintf(stdout, "%02x ", clientID[i]);
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "Slitheen super shared secret");
    for (int i=0; i< SLITHEEN_SS_LEN; i++) {
        fprintf(stdout, "%02x ", secret[i]);
    }
    fprintf(stdout, "\n");

    /* We need to represent the clientID as base64 for upstream encoding */
    slitheenID = BTOA_DataToAscii(clientID, SLITHEEN_ID_LEN); //Should be freed later with PORT_Free

    /* Generate supercrypt keys (TODO) */
    PK11SymKey *pk11symkey = NULL;
    PK11SymKey *body_key = NULL;
    PK11SymKey *header_key = NULL;
    PK11SymKey *mac_key = NULL;
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    int keyblocklen = AES_CBC_KEYLEN*3; //TODO: keyblock size... ?
    CK_BYTE *keyblock = NULL;

    if (slot == NULL) {
        return SECFailure;
    }

    keyblock = PORT_Alloc(keyblocklen);
    if (!keyblock) {
        PK11_FreeSlot(slot);
        return SECFailure;
    }

    /* Create a PKCS11 object out of the client-relay shared
     * secret */
    SECItem prfparam = { siBuffer, NULL, 0 };

    keysecitem.type = siBuffer;
    keysecitem.data = (unsigned char *) secret;
    keysecitem.len = SLITHEEN_SS_LEN;

    pk11symkey = PK11_ImportSymKey(slot, CKM_SHA256_HMAC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        PORT_ZFree(keyblock, keyblocklen);
        return SECFailure;
    }

    PRINT_KEY(0,(NULL, "Slitheen Super Shared Secret:", pk11symkey));
    /* The super encryption keys will be PRF_pk11symkey("SLITHEEN_SUPER_ENCRYPT") (22) */

    prf_context = PK11_CreateContextBySymKey(
                    CKM_NSS_TLS_PRF_GENERAL_SHA256, CKA_SIGN,
                    pk11symkey, &prfparam);
    if (!prf_context) {
        PK11_FreeSymKey(pk11symkey);
        PORT_ZFree(keyblock, keyblocklen);
        return SECFailure;
    }

    rv = PK11_DigestBegin(prf_context);
    rv |= PK11_DigestOp(prf_context,
                        (const unsigned char *)"SLITHEEN_SUPER_ENCRYPT", 22);
    rv |= PK11_DigestFinal(prf_context, keyblock, &retlen,
                            keyblocklen);

    PK11_DestroyContext(prf_context, PR_TRUE);
    prf_context = NULL;
    SECITEM_FreeItem(&prfparam, PR_FALSE);

    PRINT_BUF(0,(NULL,"Slitheen Super Key Block:", keyblock, keyblocklen));

    /* Now divide keyblock for hdr, body, and mac keys */
    keysecitem.type = siBuffer;
    keysecitem.data = (unsigned char *) keyblock;
    keysecitem.len = AES_CBC_KEYLEN;//TODO: keylen size?

    header_key = PK11_ImportSymKey(slot, CKM_AES_CBC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        PORT_ZFree(keyblock, keyblocklen);
        return SECFailure;
    }

    PRINT_KEY(0,(NULL, "Slitheen Super Header Key:", header_key));

    keysecitem.type = siBuffer;
    keysecitem.data = (unsigned char *) keyblock + AES_CBC_KEYLEN;
    keysecitem.len = AES_CBC_KEYLEN;

    body_key = PK11_ImportSymKey(slot, CKM_AES_CBC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        PORT_ZFree(keyblock, keyblocklen);
        return SECFailure;
    }

    PRINT_KEY(0,(NULL, "Slitheen Super Body Key:", body_key));

    keysecitem.type = siBuffer;
    keysecitem.data = (unsigned char *) keyblock + 2*AES_CBC_KEYLEN;
    keysecitem.len = AES_CBC_KEYLEN;

    mac_key = PK11_ImportSymKey(slot, CKM_SHA256_HMAC,
        PK11_OriginDerive, CKA_SIGN, &keysecitem, NULL);
    PK11_FreeSlot(slot);
    if (!pk11symkey) {
        PORT_ZFree(keyblock, keyblocklen);
        return SECFailure;
    }

    PRINT_KEY(0,(NULL, "Slitheen Super MAC Key:", mac_key));

    /* Store keys in global, static variables */
    super_body_key = body_key;
    super_header_key = header_key;
    super_mac_key = mac_key;

    PORT_ZFree(keyblock, keyblocklen);
    PK11_FreeSymKey(pk11symkey);
    pk11symkey = NULL;
    return SECSuccess;
}

/* Store the SlitheenID into SLITHEEN_ID_LEN bytes of slitheenid */
SSL_IMPORT SECStatus SSL_SlitheenIDGet(char *slitheenid)
{
#if SLITHEEN_ID_LEN != PTWIST_TAG_BYTES
  #error "SLITHEEN_ID_LEN must equal PTWIST_TAG_BYTES"
#endif

    PORT_Strcpy(slitheenid, slitheenID);

    return SECSuccess;
}

/* Initialize super encryption contexts */
PK11Context *superCipherInit(PK11SymKey *pk11key, CK_MECHANISM_TYPE type, PRUint8 *iv,
        unsigned int ivlen, CK_ATTRIBUTE_TYPE operation)
{
    SECItem secItem = { siBuffer, NULL, 0 };
    PK11Context *ctx = NULL;

    ctx = PK11_CreateContextBySymKey(CKM_AES_ECB, operation, pk11key, &secItem);

    return ctx;
}

/* Common encryption/decryption function */
SECStatus superCipher(PK11Context *ctx, PRUint8 *out, int *outlen,
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
SSL_IMPORT SECStatus SSL_SlitheenEncrypt(const SSL_SlitheenHeader *header,
    const PRUint8 *body, PRUint8 **encryptedblockp, PRUint32 *enclenp)
{
    return SECFailure;
}

/* Decrypt the Slitheen header of some covert data.  Pass in the
 * encrypted block and its length, as well as a pointer to a
 * (caller-allocated) SSL_SlitheenHeader struct.  The struct will be
 * filled in, and *encbodylenp will be filled in with
 * the length of the encrypted body. If (SLITHEEN_HEADER_LEN + *encbodylenp) is less
 * than encblocklen, then there is another header/body pair in this
 * encrypted block, so call both functions again (using encblocklen -
 * (SLITHEEN_HEADER_LEN + *encbodylenp) as the new encblocklen), and so on.
 */
SSL_IMPORT SECStatus SSL_SlitheenHeaderDecrypt(const PRUint8 *encryptedblock,
    PRUint32 encblocklen, SSL_SlitheenHeader *header, PRUint32 *encbodylenp)
{

    if (encblocklen < SLITHEEN_HEADER_LEN ) {
        return SECFailure;
    }

    PK11Context *ctx = superCipherInit(super_header_key, CKM_AES_ECB, NULL, 0, CKA_DECRYPT);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize ecb context\n");
        return SECFailure;
    }

    fprintf(stderr, "Encrypted slitheen header: \n");
    for (int i = 0; i< SLITHEEN_HEADER_LEN; i++) {
        fprintf(stderr, "%02x ", ((unsigned char *)encryptedblock)[i]);
    }
    fprintf(stderr, "\n");

    PRInt32 dec_len;
    unsigned char *decryptedblock = PORT_Alloc(SLITHEEN_HEADER_LEN);
    if (SECSuccess != superCipher(ctx, decryptedblock, &dec_len, SLITHEEN_HEADER_LEN, encryptedblock, SLITHEEN_HEADER_LEN)) {
        PORT_Free(decryptedblock);
        return SECFailure; //TODO: return what previous function returned
    }

    /* Populate header fields */
    header->streamID = ntohs((PRUint16) *(decryptedblock+8));
    header->datalen = ntohs((PRUint16) *(decryptedblock+10));
    header->seq = ntohl((PRUint32) *(decryptedblock));
    header->ack = ntohl((PRUint32) *(decryptedblock+4));
    header->paddinglen = ntohs(*((PRUint16 *) (decryptedblock+12)));

    fprintf(stderr, "Decrypted slitheen header: \n");
    for (int i = 0; i< SLITHEEN_HEADER_LEN; i++) {
        fprintf(stderr, "%02x ", ((unsigned char *)decryptedblock)[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "streamID: %d, datalen: %d, seq: %d, ack: %d, paddinglen: %d\n",
            header->streamID, header->datalen, header->seq, header->ack,
            header->paddinglen);

    /* Check to make sure the last 2 bytes are zeros */
    PRUint8 zeros[] = {0x00, 0x00};
    if (PORT_Memcmp(decryptedblock+14,  zeros, 2)) {
        fprintf(stderr, "Header decryption failed (missing zeros)\n");
        PORT_Free(decryptedblock);
        return SECFailure;
    }

    *encbodylenp = header->datalen;

    PORT_Free(decryptedblock);
    return SECSuccess;
}

/* Decrypt the Slitheen body of some covert data.  Pass in the
 * encrypted body and its length, as well as a pointer to a
 * the SSL_SlitheenHeader struct filled in by SSL_SlitheenHeaderDecrypt.
 * *bodyp will be set to a newly allocated block, which will be owned by
 * the caller and must be freed with PORT_Free. */
SSL_IMPORT SECStatus SSL_SlitheenBodyDecrypt(const PRUint8 *encryptedbody,
    PRUint32 encbodylen, const SSL_SlitheenHeader *header, PRUint8 **bodyp)
{
    PK11Context *ctx = superCipherInit(super_body_key, CKM_AES_CBC, NULL, 0, CKA_DECRYPT);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize ecb context\n");
        return SECFailure;
    }

    PRUint32 len = encbodylen;
    if(len %16){ //add padding to len
        len += 16 - len%16;
    }

    PRInt32 dec_len;
    unsigned char *decryptedbody = PORT_Alloc(len);
    if (SECSuccess != superCipher(ctx, decryptedbody, &dec_len, len, encryptedbody, len)) {
        PORT_Free(decryptedbody);
        return SECFailure; //TODO: return what previous function returned
    }

    fprintf(stderr, "Decrypted slitheen body (%d bytes):", dec_len);
    for (int i=0; i< dec_len; i++){
        fprintf(stderr, "%02x ", decryptedbody[i]);
    }
    fprintf(stderr, "\n");

    *bodyp = decryptedbody;

    return SECSuccess;
}
