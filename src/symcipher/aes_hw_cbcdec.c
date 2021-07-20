/*
 * Copyright (c) 2021 Caleb Daniels
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#include "crypto.h"

/* see bearssl_block.h */
void
br_aes_hw_cbcdec_init(br_aes_hw_cbcdec_keys *ctx,
        const void *key, size_t len)
{
    ctx->vtable = &br_aes_hw_cbcdec_vtable;
    memcpy(ctx->key, key, len);
    ctx->keylen = len;
}

/* see bearssl_block.h */
void
br_aes_hw_cbcdec_run(const br_aes_hw_cbcdec_keys *ctx,
        void *iv, void *data, size_t len)
{
    HWCryptoStart();

    uint8_t * buf = data;

    HWCryptoKeySize keysize = HWCRYPTO_KEYSIZE_128;
    switch (ctx->keylen)
    {
        case 16:
            keysize = HWCRYPTO_KEYSIZE_128;
            break;
        case 32:
            keysize = HWCRYPTO_KEYSIZE_256;
            break;
        default:
            SYS_DEBUG_PRINT(SYS_ERROR_ERROR, "BearSSL", "HW AES KeySize not implemented - %d", ctx->keylen);
            break;
    }

    size_t i = 0;
    while (i < len)
    {
        size_t chunk_size = len - i;
        if (chunk_size > CRYPTO_MAX_CHUNK_SIZE)
            chunk_size = CRYPTO_MAX_CHUNK_SIZE;
        HWCryptoUpdate(&buf[i], chunk_size, (uint8_t*)ctx->key, iv, &buf[i], HWCRYPTO_DEC, HWCRYPTO_ALGO_AES_CBC, keysize);
        i += chunk_size;
    }

    HWCryptoFinish();
}

/* see bearssl_block.h */
const br_block_cbcdec_class br_aes_hw_cbcdec_vtable = {
    sizeof (br_aes_big_cbcdec_keys),
    16,
    4,
    (void (*)(const br_block_cbcdec_class **, const void *, size_t))
    & br_aes_hw_cbcdec_init,
    (void (*)(const br_block_cbcdec_class * const *, void *, void *, size_t))
    & br_aes_hw_cbcdec_run
};