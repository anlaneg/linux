/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * AEAD: Authenticated Encryption with Associated Data
 * 
 * Copyright (c) 2007-2015 Herbert Xu <herbert@gondor.apana.org.au>
 */

#ifndef _CRYPTO_AEAD_H
#define _CRYPTO_AEAD_H

#include <linux/atomic.h>
#include <linux/container_of.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/types.h>

/**
 * DOC: Authenticated Encryption With Associated Data (AEAD) Cipher API
 *
 * The AEAD cipher API is used with the ciphers of type CRYPTO_ALG_TYPE_AEAD
 * (listed as type "aead" in /proc/crypto)
 *
 * The most prominent examples for this type of encryption is GCM and CCM.
 * However, the kernel supports other types of AEAD ciphers which are defined
 * with the following cipher string:
 *
 *	authenc(keyed message digest, block cipher)
 *
 * For example: authenc(hmac(sha256), cbc(aes))
 *
 * The example code provided for the symmetric key cipher operation applies
 * here as well. Naturally all *skcipher* symbols must be exchanged the *aead*
 * pendants discussed in the following. In addition, for the AEAD operation,
 * the aead_request_set_ad function must be used to set the pointer to the
 * associated data memory location before performing the encryption or
 * decryption operation. Another deviation from the asynchronous block cipher
 * operation is that the caller should explicitly check for -EBADMSG of the
 * crypto_aead_decrypt. That error indicates an authentication error, i.e.
 * a breach in the integrity of the message. In essence, that -EBADMSG error
 * code is the key bonus an AEAD cipher has over "standard" block chaining
 * modes.
 *
 * Memory Structure:
 *
 * The source scatterlist must contain the concatenation of
 * associated data || plaintext or ciphertext.
 *
 * The destination scatterlist has the same layout, except that the plaintext
 * (resp. ciphertext) will grow (resp. shrink) by the authentication tag size
 * during encryption (resp. decryption). The authentication tag is generated
 * during the encryption operation and appended to the ciphertext. During
 * decryption, the authentication tag is consumed along with the ciphertext and
 * used to verify the integrity of the plaintext and the associated data.
 *
 * In-place encryption/decryption is enabled by using the same scatterlist
 * pointer for both the source and destination.
 *
 * Even in the out-of-place case, space must be reserved in the destination for
 * the associated data, even though it won't be written to.  This makes the
 * in-place and out-of-place cases more consistent.  It is permissible for the
 * "destination" associated data to alias the "source" associated data.
 *
 * As with the other scatterlist crypto APIs, zero-length scatterlist elements
 * are not allowed in the used part of the scatterlist.  Thus, if there is no
 * associated data, the first element must point to the plaintext/ciphertext.
 *
 * To meet the needs of IPsec, a special quirk applies to rfc4106, rfc4309,
 * rfc4543, and rfc7539esp ciphers.  For these ciphers, the final 'ivsize' bytes
 * of the associated data buffer must contain a second copy of the IV.  This is
 * in addition to the copy passed to aead_request_set_crypt().  These two IV
 * copies must not differ; different implementations of the same algorithm may
 * behave differently in that case.  Note that the algorithm might not actually
 * treat the IV as associated data; nevertheless the length passed to
 * aead_request_set_ad() must include it.
 */

struct crypto_aead;
struct scatterlist;

/**
 *	struct aead_request - AEAD request
 *	@base: Common attributes for async crypto requests
 *	@assoclen: Length in bytes of associated data for authentication
 *	@cryptlen: Length of data to be encrypted or decrypted
 *	@iv: Initialisation vector
 *	@src: Source data
 *	@dst: Destination data
 *	@__ctx: Start of private context data
 */
struct aead_request {
	struct crypto_async_request base;

	unsigned int assoclen;
	unsigned int cryptlen;

	u8 *iv;

	struct scatterlist *src;//源数据
	struct scatterlist *dst;//加工后数据

	void *__ctx[] CRYPTO_MINALIGN_ATTR;
};

/*
 * struct crypto_istat_aead - statistics for AEAD algorithm
 * @encrypt_cnt:	number of encrypt requests
 * @encrypt_tlen:	total data size handled by encrypt requests
 * @decrypt_cnt:	number of decrypt requests
 * @decrypt_tlen:	total data size handled by decrypt requests
 * @err_cnt:		number of error for AEAD requests
 */
struct crypto_istat_aead {
	atomic64_t encrypt_cnt;
	atomic64_t encrypt_tlen;
	atomic64_t decrypt_cnt;
	atomic64_t decrypt_tlen;
	atomic64_t err_cnt;
};

/**
 * struct aead_alg - AEAD cipher definition
 * @maxauthsize: Set the maximum authentication tag size supported by the
 *		 transformation. A transformation may support smaller tag sizes.
 *		 As the authentication tag is a message digest to ensure the
 *		 integrity of the encrypted data, a consumer typically wants the
 *		 largest authentication tag possible as defined by this
 *		 variable.
 * @setauthsize: Set authentication size for the AEAD transformation. This
 *		 function is used to specify the consumer requested size of the
 * 		 authentication tag to be either generated by the transformation
 *		 during encryption or the size of the authentication tag to be
 *		 supplied during the decryption operation. This function is also
 *		 responsible for checking the authentication tag size for
 *		 validity.
 * @setkey: see struct skcipher_alg
 * @encrypt: see struct skcipher_alg
 * @decrypt: see struct skcipher_alg
 * @stat: statistics for AEAD algorithm
 * @ivsize: see struct skcipher_alg
 * @chunksize: see struct skcipher_alg
 * @init: Initialize the cryptographic transformation object. This function
 *	  is used to initialize the cryptographic transformation object.
 *	  This function is called only once at the instantiation time, right
 *	  after the transformation context was allocated. In case the
 *	  cryptographic hardware has some special requirements which need to
 *	  be handled by software, this function shall check for the precise
 *	  requirement of the transformation and put any software fallbacks
 *	  in place.
 * @exit: Deinitialize the cryptographic transformation object. This is a
 *	  counterpart to @init, used to remove various changes set in
 *	  @init.
 * @base: Definition of a generic crypto cipher algorithm.
 *
 * All fields except @ivsize is mandatory and must be filled.
 */
struct aead_alg {
	int (*setkey)(struct crypto_aead *tfm, const u8 *key,
	              unsigned int keylen);
	int (*setauthsize)(struct crypto_aead *tfm, unsigned int authsize);
	int (*encrypt)(struct aead_request *req);
	int (*decrypt)(struct aead_request *req);
	int (*init)(struct crypto_aead *tfm);
	void (*exit)(struct crypto_aead *tfm);

#ifdef CONFIG_CRYPTO_STATS
	struct crypto_istat_aead stat;
#endif

	unsigned int ivsize;
	unsigned int maxauthsize;
	unsigned int chunksize;

	struct crypto_alg base;
};

struct crypto_aead {
	unsigned int authsize;
	unsigned int reqsize;

	struct crypto_tfm base;
};

static inline struct crypto_aead *__crypto_aead_cast(struct crypto_tfm *tfm)
{
	return container_of(tfm, struct crypto_aead, base);
}

/**
 * crypto_alloc_aead() - allocate AEAD cipher handle
 * @alg_name: is the cra_name / name or cra_driver_name / driver name of the
 *	     AEAD cipher
 * @type: specifies the type of the cipher
 * @mask: specifies the mask for the cipher
 *
 * Allocate a cipher handle for an AEAD. The returned struct
 * crypto_aead is the cipher handle that is required for any subsequent
 * API invocation for that AEAD.
 *
 * Return: allocated cipher handle in case of success; IS_ERR() is true in case
 *	   of an error, PTR_ERR() returns the error code.
 */
struct crypto_aead *crypto_alloc_aead(const char *alg_name, u32 type, u32 mask);

static inline struct crypto_tfm *crypto_aead_tfm(struct crypto_aead *tfm)
{
	return &tfm->base;
}

/**
 * crypto_free_aead() - zeroize and free aead handle
 * @tfm: cipher handle to be freed
 *
 * If @tfm is a NULL or error pointer, this function does nothing.
 */
static inline void crypto_free_aead(struct crypto_aead *tfm)
{
	crypto_destroy_tfm(tfm, crypto_aead_tfm(tfm));
}

/**
 * crypto_has_aead() - Search for the availability of an aead.
 * @alg_name: is the cra_name / name or cra_driver_name / driver name of the
 *	      aead
 * @type: specifies the type of the aead
 * @mask: specifies the mask for the aead
 *
 * Return: true when the aead is known to the kernel crypto API; false
 *	   otherwise
 */
int crypto_has_aead(const char *alg_name, u32 type, u32 mask);

static inline const char *crypto_aead_driver_name(struct crypto_aead *tfm)
{
	return crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm));
}

static inline struct aead_alg *crypto_aead_alg(struct crypto_aead *tfm)
{
	return container_of(crypto_aead_tfm(tfm)->__crt_alg,
			    struct aead_alg, base);
}

static inline unsigned int crypto_aead_alg_ivsize(struct aead_alg *alg)
{
	return alg->ivsize;
}

/**
 * crypto_aead_ivsize() - obtain IV size
 * @tfm: cipher handle
 *
 * The size of the IV for the aead referenced by the cipher handle is
 * returned. This IV size may be zero if the cipher does not need an IV.
 *
 * Return: IV size in bytes
 */
static inline unsigned int crypto_aead_ivsize(struct crypto_aead *tfm)
{
	return crypto_aead_alg_ivsize(crypto_aead_alg(tfm));
}

/**
 * crypto_aead_authsize() - obtain maximum authentication data size
 * @tfm: cipher handle
 *
 * The maximum size of the authentication data for the AEAD cipher referenced
 * by the AEAD cipher handle is returned. The authentication data size may be
 * zero if the cipher implements a hard-coded maximum.
 *
 * The authentication data may also be known as "tag value".
 *
 * Return: authentication data size / tag size in bytes
 */
static inline unsigned int crypto_aead_authsize(struct crypto_aead *tfm)
{
	return tfm->authsize;
}

static inline unsigned int crypto_aead_alg_maxauthsize(struct aead_alg *alg)
{
	return alg->maxauthsize;
}

static inline unsigned int crypto_aead_maxauthsize(struct crypto_aead *aead)
{
	return crypto_aead_alg_maxauthsize(crypto_aead_alg(aead));
}

/**
 * crypto_aead_blocksize() - obtain block size of cipher
 * @tfm: cipher handle
 *
 * The block size for the AEAD referenced with the cipher handle is returned.
 * The caller may use that information to allocate appropriate memory for the
 * data returned by the encryption or decryption operation
 *
 * Return: block size of cipher
 */
static inline unsigned int crypto_aead_blocksize(struct crypto_aead *tfm)
{
	return crypto_tfm_alg_blocksize(crypto_aead_tfm(tfm));
}

static inline unsigned int crypto_aead_alignmask(struct crypto_aead *tfm)
{
	return crypto_tfm_alg_alignmask(crypto_aead_tfm(tfm));
}

static inline u32 crypto_aead_get_flags(struct crypto_aead *tfm)
{
	return crypto_tfm_get_flags(crypto_aead_tfm(tfm));
}

static inline void crypto_aead_set_flags(struct crypto_aead *tfm, u32 flags)
{
	crypto_tfm_set_flags(crypto_aead_tfm(tfm), flags);
}

static inline void crypto_aead_clear_flags(struct crypto_aead *tfm, u32 flags)
{
	crypto_tfm_clear_flags(crypto_aead_tfm(tfm), flags);
}

/**
 * crypto_aead_setkey() - set key for cipher
 * @tfm: cipher handle
 * @key: buffer holding the key
 * @keylen: length of the key in bytes
 *
 * The caller provided key is set for the AEAD referenced by the cipher
 * handle.
 *
 * Note, the key length determines the cipher type. Many block ciphers implement
 * different cipher modes depending on the key size, such as AES-128 vs AES-192
 * vs. AES-256. When providing a 16 byte key for an AES cipher handle, AES-128
 * is performed.
 *
 * Return: 0 if the setting of the key was successful; < 0 if an error occurred
 */
int crypto_aead_setkey(struct crypto_aead *tfm,
		       const u8 *key, unsigned int keylen);

/**
 * crypto_aead_setauthsize() - set authentication data size
 * @tfm: cipher handle
 * @authsize: size of the authentication data / tag in bytes
 *
 * Set the authentication data size / tag size. AEAD requires an authentication
 * tag (or MAC) in addition to the associated data.
 *
 * Return: 0 if the setting of the key was successful; < 0 if an error occurred
 */
int crypto_aead_setauthsize(struct crypto_aead *tfm, unsigned int authsize);

static inline struct crypto_aead *crypto_aead_reqtfm(struct aead_request *req)
{
	return __crypto_aead_cast(req->base.tfm);
}

/**
 * crypto_aead_encrypt() - encrypt plaintext
 * @req: reference to the aead_request handle that holds all information
 *	 needed to perform the cipher operation
 *
 * Encrypt plaintext data using the aead_request handle. That data structure
 * and how it is filled with data is discussed with the aead_request_*
 * functions.
 *
 * IMPORTANT NOTE The encryption operation creates the authentication data /
 *		  tag. That data is concatenated with the created ciphertext.
 *		  The ciphertext memory size is therefore the given number of
 *		  block cipher blocks + the size defined by the
 *		  crypto_aead_setauthsize invocation. The caller must ensure
 *		  that sufficient memory is available for the ciphertext and
 *		  the authentication tag.
 *
 * Return: 0 if the cipher operation was successful; < 0 if an error occurred
 */
int crypto_aead_encrypt(struct aead_request *req);

/**
 * crypto_aead_decrypt() - decrypt ciphertext
 * @req: reference to the aead_request handle that holds all information
 *	 needed to perform the cipher operation
 *
 * Decrypt ciphertext data using the aead_request handle. That data structure
 * and how it is filled with data is discussed with the aead_request_*
 * functions.
 *
 * IMPORTANT NOTE The caller must concatenate the ciphertext followed by the
 *		  authentication data / tag. That authentication data / tag
 *		  must have the size defined by the crypto_aead_setauthsize
 *		  invocation.
 *
 *
 * Return: 0 if the cipher operation was successful; -EBADMSG: The AEAD
 *	   cipher operation performs the authentication of the data during the
 *	   decryption operation. Therefore, the function returns this error if
 *	   the authentication of the ciphertext was unsuccessful (i.e. the
 *	   integrity of the ciphertext or the associated data was violated);
 *	   < 0 if an error occurred.
 */
//解密
int crypto_aead_decrypt(struct aead_request *req);

/**
 * DOC: Asynchronous AEAD Request Handle
 *
 * The aead_request data structure contains all pointers to data required for
 * the AEAD cipher operation. This includes the cipher handle (which can be
 * used by multiple aead_request instances), pointer to plaintext and
 * ciphertext, asynchronous callback function, etc. It acts as a handle to the
 * aead_request_* API calls in a similar way as AEAD handle to the
 * crypto_aead_* API calls.
 */

/**
 * crypto_aead_reqsize() - obtain size of the request data structure
 * @tfm: cipher handle
 *
 * Return: number of bytes
 */
static inline unsigned int crypto_aead_reqsize(struct crypto_aead *tfm)
{
	return tfm->reqsize;
}

/**
 * aead_request_set_tfm() - update cipher handle reference in request
 * @req: request handle to be modified
 * @tfm: cipher handle that shall be added to the request handle
 *
 * Allow the caller to replace the existing aead handle in the request
 * data structure with a different one.
 */
static inline void aead_request_set_tfm(struct aead_request *req,
					struct crypto_aead *tfm)
{
	req->base.tfm = crypto_aead_tfm(tfm);
}

/**
 * aead_request_alloc() - allocate request data structure
 * @tfm: cipher handle to be registered with the request
 * @gfp: memory allocation flag that is handed to kmalloc by the API call.
 *
 * Allocate the request data structure that must be used with the AEAD
 * encrypt and decrypt API calls. During the allocation, the provided aead
 * handle is registered in the request data structure.
 *
 * Return: allocated request handle in case of success, or NULL if out of memory
 */
static inline struct aead_request *aead_request_alloc(struct crypto_aead *tfm,
						      gfp_t gfp)
{
	struct aead_request *req;

	req = kmalloc(sizeof(*req) + crypto_aead_reqsize(tfm), gfp);

	if (likely(req))
		aead_request_set_tfm(req, tfm);

	return req;
}

/**
 * aead_request_free() - zeroize and free request data structure
 * @req: request data structure cipher handle to be freed
 */
static inline void aead_request_free(struct aead_request *req)
{
	kfree_sensitive(req);
}

/**
 * aead_request_set_callback() - set asynchronous callback function
 * @req: request handle
 * @flags: specify zero or an ORing of the flags
 *	   CRYPTO_TFM_REQ_MAY_BACKLOG the request queue may back log and
 *	   increase the wait queue beyond the initial maximum size;
 *	   CRYPTO_TFM_REQ_MAY_SLEEP the request processing may sleep
 * @compl: callback function pointer to be registered with the request handle
 * @data: The data pointer refers to memory that is not used by the kernel
 *	  crypto API, but provided to the callback function for it to use. Here,
 *	  the caller can provide a reference to memory the callback function can
 *	  operate on. As the callback function is invoked asynchronously to the
 *	  related functionality, it may need to access data structures of the
 *	  related functionality which can be referenced using this pointer. The
 *	  callback function can access the memory via the "data" field in the
 *	  crypto_async_request data structure provided to the callback function.
 *
 * Setting the callback function that is triggered once the cipher operation
 * completes
 *
 * The callback function is registered with the aead_request handle and
 * must comply with the following template::
 *
 *	void callback_function(struct crypto_async_request *req, int error)
 */
static inline void aead_request_set_callback(struct aead_request *req,
					     u32 flags,
					     crypto_completion_t compl,
					     void *data)
{
	req->base.complete = compl;
	req->base.data = data;
	req->base.flags = flags;
}

/**
 * aead_request_set_crypt - set data buffers
 * @req: request handle
 * @src: source scatter / gather list
 * @dst: destination scatter / gather list
 * @cryptlen: number of bytes to process from @src
 * @iv: IV for the cipher operation which must comply with the IV size defined
 *      by crypto_aead_ivsize()
 *
 * Setting the source data and destination data scatter / gather lists which
 * hold the associated data concatenated with the plaintext or ciphertext. See
 * below for the authentication tag.
 *
 * For encryption, the source is treated as the plaintext and the
 * destination is the ciphertext. For a decryption operation, the use is
 * reversed - the source is the ciphertext and the destination is the plaintext.
 *
 * The memory structure for cipher operation has the following structure:
 *
 * - AEAD encryption input:  assoc data || plaintext
 * - AEAD encryption output: assoc data || ciphertext || auth tag
 * - AEAD decryption input:  assoc data || ciphertext || auth tag
 * - AEAD decryption output: assoc data || plaintext
 *
 * Albeit the kernel requires the presence of the AAD buffer, however,
 * the kernel does not fill the AAD buffer in the output case. If the
 * caller wants to have that data buffer filled, the caller must either
 * use an in-place cipher operation (i.e. same memory location for
 * input/output memory location).
 */
static inline void aead_request_set_crypt(struct aead_request *req,
					  struct scatterlist *src,
					  struct scatterlist *dst,
					  unsigned int cryptlen, u8 *iv)
{
	req->src = src;
	req->dst = dst;
	req->cryptlen = cryptlen;
	req->iv = iv;
}

/**
 * aead_request_set_ad - set associated data information
 * @req: request handle
 * @assoclen: number of bytes in associated data
 *
 * Setting the AD information.  This function sets the length of
 * the associated data.
 */
static inline void aead_request_set_ad(struct aead_request *req,
				       unsigned int assoclen)
{
	req->assoclen = assoclen;
}

#endif	/* _CRYPTO_AEAD_H */
