#ifndef __SLITHEEN_H__
#define __SLITHEEN_H__

#include "prtypes.h"
#include "ptwist.h"

SECStatus SlitheenEnable(sslSocket *ss, PRBool on);
PRBool SlitheenEnabled(const sslSocket *ss);

#endif
