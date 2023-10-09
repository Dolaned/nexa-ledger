// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CASHLIB_H
#define CASHLIB_H

#define SLAPI __attribute__((visibility("default")))

#include "stdint.h"
#include <stdbool.h>

/** Sign one input of a transaction using a Schnorr signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI int signTxOneInputUsingSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

/* DEPRECATED: same as SignTxOneInputUsingSchnorr */
SLAPI int SignTxSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

SLAPI int ledgerTestFunction(const int x);

#endif /* CASHLIB_H */
