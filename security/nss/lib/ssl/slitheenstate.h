#ifndef __SLITHEENSTATE_H__
#define __SLITHEENSTATE_H__

#include "ptwist.h"

/*
 * Possible Slitheen states for this connection to be in.
 *
 * SSLSlitheenStateOff: Slitheen is not enabled for this socket
 * SSLSlitheenStateNotStarted: Slitheen enabled, not yet started
 * SSLSlitheenStateTagged: A Slitheen tag has been sent
 * SSLSlitheenStateNack: This socket is not for use with Slitheen
 * SSLSlitheenStateAcknowledged: This socket is ready for use by Slitheen
 */
typedef enum {
    SSLSlitheenStateOff,
    SSLSlitheenStateNotStarted,
    SSLSlitheenStateTagged,
    SSLSlitheenStateNack,
    SSLSlitheenStateAcknowledged
} SSLSlitheenState;

/* The size of the Slitheen client-relay shared secret, in bytes */
#define SLITHEEN_SS_LEN 16

/* The size of a Slitheen public key (just the main, not the twist) */
#define SLITHEEN_PUBKEY_LEN PTWIST_BYTES

#endif
