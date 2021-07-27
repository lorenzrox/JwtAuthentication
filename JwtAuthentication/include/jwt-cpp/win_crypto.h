#ifndef JWT_CPP_WIN_CRYPTO_H
#define JWT_CPP_WIN_CRYPTO_H

#define NOMINMAX
#define _WINSOCKAPI_

#include <Windows.h>
#include <capi.h>
#include <iostream>
#include <memory>
#include <vector>

#include "error.h"

#ifdef MIN
#undef MIN
#endif

#ifdef MAX
#undef MAX
#endif

namespace jwt {
	namespace crypto {
		namespace details {
			class CCryptContext {
			public:
				CCryptContext() : provider(NULL) {}

				~CCryptContext() { reset(); }

				CCryptContext(CCryptContext&& other) noexcept : provider(other.provider) { other.provider = NULL; }

				CCryptContext& operator=(CCryptContext&& other) noexcept {
					if (provider != other.provider) {
						reset();

						provider = other.provider;
						other.provider = NULL;
					}

					return *this;
				}

				explicit operator bool() const noexcept { return provider != NULL; }

				operator HCRYPTPROV() const noexcept { return provider; }

				HCRYPTPROV* operator&() {
					reset();
					return &provider;
				}

				HCRYPTPROV get() const noexcept { return provider; }

				void swap(CCryptContext& other) noexcept { std::swap(other.provider, provider); }

				void reset() {
					if (provider != NULL) {
						CryptReleaseContext(provider, 0);
						provider = NULL;
					}
				}

				CCryptContext(const CCryptContext&) = delete;
				CCryptContext& operator=(const CCryptContext&) = delete;

			private:
				HCRYPTPROV provider;
			};

			class CCryptKey {
			public:
				CCryptKey() : key(NULL) {}

				~CCryptKey() { reset(); }

				CCryptKey(CCryptKey&& other) noexcept : key(other.key) { other.key = NULL; }

				CCryptKey& operator=(CCryptKey&& other) noexcept {
					if (key != other.key) {
						reset();

						key = other.key;
						other.key = NULL;
					}

					return *this;
				}

				explicit operator bool() const noexcept { return key != NULL; }

				operator HCRYPTKEY() const noexcept { return key; }

				HCRYPTKEY* operator&() {
					reset();
					return &key;
				}

				HCRYPTKEY get() const noexcept { return key; }

				void swap(CCryptKey& other) noexcept { std::swap(other.key, key); }

				void reset() noexcept {
					if (key != NULL) {
						CryptDestroyKey(key);
						key = NULL;
					}
				}

				CCryptKey(const CCryptKey&) = delete;
				CCryptKey& operator=(const CCryptKey&) = delete;

			private:
				HCRYPTKEY key;
			};

			class CCryptHash {
			public:
				CCryptHash() : hash(NULL) {}

				~CCryptHash() { reset(); }

				CCryptHash(CCryptHash&& other) noexcept : hash(other.hash) { other.hash = NULL; }

				CCryptHash& operator=(CCryptHash&& other) noexcept {
					if (hash != other.hash) {
						reset();

						hash = other.hash;
						other.hash = NULL;
					}

					return *this;
				}

				explicit operator bool() const noexcept { return hash != NULL; }

				operator HCRYPTHASH() const noexcept { return hash; }

				HCRYPTHASH* operator&() {
					reset();
					return &hash;
				}

				HCRYPTHASH get() const noexcept { return hash; }

				void swap(CCryptHash& other) noexcept { std::swap(other.hash, hash); }

				void reset() noexcept {
					if (hash != NULL) {
						CryptDestroyHash(hash);
						hash = NULL;
					}
				}

				bool computeHash(const std::string& data, std::string& result) {
					result.clear();

					DWORD dwDataLen = 0;
					if (!CryptGetHashParam(hash, HP_HASHVAL, NULL, &dwDataLen, 0)) { return false; }

					result.resize(dwDataLen);

					return CryptGetHashParam(hash, HP_HASHVAL, reinterpret_cast<BYTE*>(&result[0]), &dwDataLen, 0);
				}

				CCryptHash(const CCryptHash&) = delete;
				CCryptHash& operator=(const CCryptHash&) = delete;

			private:
				HCRYPTHASH hash;
			};

			template<typename T>
			class LocalBuffer {
			public:
				LocalBuffer() : data(nullptr) {}

				LocalBuffer(size_t size) : data(LocalAlloc(0, size * sizeof(T))) {}

				LocalBuffer(LocalBuffer<T>&& other) noexcept : data(other.data) { other.data = nullptr; }

				~LocalBuffer() { reset(); }

				LocalBuffer& operator=(LocalBuffer&& other) noexcept {
					if (data != other.data) {
						reset();

						data = other.data;
						other.data = nullptr;
					}

					return *this;
				}

				explicit operator bool() const noexcept { return data != nullptr; }

				T* get() const noexcept { return data; }

				T** operator&() {
					reset();
					return &data;
				}

				void swap(LocalBuffer& other) noexcept { std::swap(other.data, data); }

				void reset() {
					if (data != nullptr) {
						LocalFree(data);
						data = 0;
					}
				}

				LocalBuffer(const LocalBuffer&) = delete;
				LocalBuffer& operator=(const LocalBuffer&) = delete;

			private:
				T* data;
			};
		} // namespace details

		using details::CCryptContext;
		using details::CCryptHash;
		using details::CCryptKey;
		using details::LocalBuffer;

		namespace helper {

			/**
			 * \brief Extract the public key of a pem certificate
			 *
			 * \param certstr	String containing the certificate encoded as pem
			 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
			 * \param ec		error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& password,
														std::error_code& ec) {
				ec.clear();

				DWORD dwBufferLen = 0;
				if (!CryptStringToBinaryA(certstr.data(), certstr.size(), CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen,
										  NULL, NULL)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				std::vector<BYTE> buffer(dwBufferLen);
				if (!CryptStringToBinaryA(certstr.data(), certstr.size(), CRYPT_STRING_BASE64HEADER, buffer.data(),
										  &dwBufferLen, NULL, NULL)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				DWORD cbSignedContentInfoBuffer = 0;
				LocalBuffer<BYTE> signedContentInfoBuffer;
				if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CERT, buffer.data(), dwBufferLen,
										 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
										 &signedContentInfoBuffer, &cbSignedContentInfoBuffer)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				auto pSignedContentInfo = reinterpret_cast<PCERT_SIGNED_CONTENT_INFO>(signedContentInfoBuffer.get());

				CCRYPT_OID_INFO* oidInfo =
					CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pSignedContentInfo->SignatureAlgorithm.pszObjId, 0);
				if (!oidInfo || oidInfo->dwGroupId != CRYPT_SIGN_ALG_OID_GROUP_ID) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				DWORD cbCertInfoBuffer = 0;
				LocalBuffer<BYTE> certInfoBuffer;
				if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED,
										 pSignedContentInfo->ToBeSigned.pbData, pSignedContentInfo->ToBeSigned.cbData,
										 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &certInfoBuffer,
										 &cbCertInfoBuffer)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				auto pCertInfo = reinterpret_cast<PCERT_INFO>(certInfoBuffer.get());

				CCryptContext context;
				if (!CryptAcquireContext(&context, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				CCryptKey key;
				if (!CryptImportPublicKeyInfo(context.get(), X509_ASN_ENCODING, &pCertInfo->SubjectPublicKeyInfo,
											  &key)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				DWORD cbBlobSize = 0;
				if (!CryptExportKey(key.get(), NULL, PUBLICKEYBLOB, 0, NULL, &cbBlobSize)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				std::string result(cbBlobSize, '\0');
				if (!CryptExportKey(key.get(), NULL, PUBLICKEYBLOB, 0, reinterpret_cast<BYTE*>(&result[0]),
									&cbBlobSize)) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}

				return result;
			}

			/**
			 * \brief Convert the certificate provided as base64 DER to PEM.
			 *
			 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
			 * (here)[https://tools.ietf.org/html/rfc7517#section-4.7]
			 *
			 * \tparam Decode is callabled, taking a string_type and returns a string_type.
			 * It should ensure the padding of the input and then base64 decode and return
			 * the results.
			 *
			 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
			 * \param decode 				The function to decode the cert
			 * \param ec					error_code for error_detection (gets cleared if no error occures)
			 */
			template<typename Decode>
			std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, Decode decode,
												  std::error_code& ec) {
				ec.clear();

				const auto decodedStr = decode(cert_base64_der_str);

				DWORD cbKeyInfoBuffer = 0;
				LocalBuffer<BYTE> keyInfoBuffer;
				if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
										 reinterpret_cast<const BYTE*>(decodedStr.data()), decodedStr.size(),
										 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &keyInfoBuffer,
										 &cbKeyInfoBuffer)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				CCryptContext context;
				if (!CryptAcquireContext(&context, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				CCryptKey key;
				if (!CryptImportPublicKeyInfo(context.get(), X509_ASN_ENCODING,
											  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(keyInfoBuffer.get()), &key)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				DWORD cbPKey = 0;
				if (!CryptExportPublicKeyInfo(context.get(), AT_KEYEXCHANGE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											  NULL, &cbPKey)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				std::vector<BYTE> pkeyBuffer(cbPKey);
				if (!CryptExportPublicKeyInfo(context.get(), AT_KEYEXCHANGE, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(pkeyBuffer.data()), &cbPKey)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pkeyBuffer.data(),
										 CRYPT_ENCODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &keyInfoBuffer,
										 &cbKeyInfoBuffer)) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				DWORD cbKeyBlob = 0;
				if (!CryptBinaryToStringA(keyInfoBuffer.get(), cbKeyInfoBuffer, CRYPT_STRING_BASE64HEADER, NULL,
										  &cbKeyBlob)) {
					ec = error::rsa_error::write_cert_failed;
					return {};
				}

				std::string keyBlob(cbKeyInfoBuffer, '\0');
				if (!CryptBinaryToStringA(keyInfoBuffer.get(), cbKeyInfoBuffer, CRYPT_STRING_BASE64HEADER, &keyBlob[0],
										  &cbKeyBlob)) {
					ec = error::rsa_error::write_cert_failed;
					return {};
				}

				return keyBlob;
			}

			/**
			 * \brief Load a public key from a string.
			 *
			 * The string should contain a pem encoded certificate or public key
			 *
			 * \param certstr	String containing the certificate encoded as pem
			 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
			 * \param ec		error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::string load_public_key_from_string(const std::string& pubkey, const std::string& password,
														   std::error_code& ec) {
				ec.clear();

				if (pubkey.find("-----BEGIN CERTIFICATE-----") == 0) {
					return extract_pubkey_from_cert(pubkey, password, ec);
				} else {
					DWORD dwBufferLen = 0;
					if (!CryptStringToBinaryA(pubkey.data(), pubkey.size(), CRYPT_STRING_BASE64HEADER, NULL,
											  &dwBufferLen, NULL, NULL)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					std::vector<BYTE> buffer(dwBufferLen);
					if (!CryptStringToBinaryA(pubkey.data(), pubkey.size(), CRYPT_STRING_BASE64HEADER, buffer.data(),
											  &dwBufferLen, NULL, NULL)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					DWORD cbKeyInfoBuffer = 0;
					LocalBuffer<BYTE> keyInfoBuffer;
					if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, buffer.data(), buffer.size(),
											 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &keyInfoBuffer,
											 &cbKeyInfoBuffer)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					CCryptContext context;
					if (!CryptAcquireContext(&context, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					CCryptKey key;
					if (!CryptImportPublicKeyInfo(context.get(), X509_ASN_ENCODING,
												  reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(keyInfoBuffer.get()), &key)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					DWORD cbKeyBlob = 0;
					if (!CryptExportKey(key.get(), NULL, PUBLICKEYBLOB, 0, NULL, &cbKeyBlob)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					std::string keyBlob(cbKeyBlob, '\0');
					if (!CryptExportKey(key.get(), NULL, PUBLICKEYBLOB, 0, reinterpret_cast<BYTE*>(&keyBlob[0]),
										&cbKeyBlob)) {
						ec = error::rsa_error::load_key_bio_read;
						return {};
					}

					return keyBlob;
				}
			}

			/**
			 * \brief Load a private key from a string.
			 *
			 * \param key		String containing a private key as pem
			 * \param pw		Password used to decrypt key (leave empty if not encrypted)
			 * \param ec		error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::string load_private_key_from_string(const std::string& privkey, const std::string& password,
															std::error_code& ec) {
				ec.clear();

				DWORD dwBufferLen = 0;
				if (!CryptStringToBinaryA(privkey.data(), privkey.size(), CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen,
										  NULL, NULL)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				std::vector<BYTE> buffer(dwBufferLen);
				if (!CryptStringToBinaryA(privkey.data(), privkey.size(), CRYPT_STRING_BASE64HEADER, buffer.data(),
										  &dwBufferLen, NULL, NULL)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				DWORD cbKeyInfoBuffer = 0;
				LocalBuffer<BYTE> keyInfoBuffer;
				if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, buffer.data(), buffer.size(),
										 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &keyInfoBuffer,
										 &cbKeyInfoBuffer)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				auto pPrivateKeyInfo = reinterpret_cast<PCRYPT_PRIVATE_KEY_INFO>(keyInfoBuffer.get());

				DWORD cbPrivateKeyBuffer = 0;
				LocalBuffer<BYTE> privateKeyInfoBuffer;
				if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pPrivateKeyInfo->PrivateKey.pbData,
										 pPrivateKeyInfo->PrivateKey.cbData,
										 CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &keyInfoBuffer,
										 &cbKeyInfoBuffer)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				CCryptContext context;
				if (!CryptAcquireContext(&context, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				CCryptKey key;
				if (!CryptImportKey(context.get(), keyInfoBuffer.get(), cbKeyInfoBuffer, NULL, CRYPT_EXPORTABLE,
									&key)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				DWORD cbKeyBlob = 0;
				if (!CryptExportKey(key.get(), NULL, PRIVATEKEYBLOB, 0, NULL, &cbKeyBlob)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				std::string keyBlob(cbKeyBlob, '\0');
				if (!CryptExportKey(key.get(), NULL, PRIVATEKEYBLOB, 0, reinterpret_cast<BYTE*>(&keyBlob[0]),
									&cbKeyBlob)) {
					ec = error::rsa_error::load_key_bio_read;
					return {};
				}

				return keyBlob;
			}

			/**
			 * \brief Load a public key from a string.
			 *
			 * The string should contain a pem encoded certificate or public key
			 *
			 * \param certstr	String containing the certificate or key encoded as pem
			 * \param pw		Password used to decrypt certificate or key (leave empty if not encrypted)
			 * \throw			rsa_exception if an error occurred
			 */
			inline std::string load_public_key_from_string(const std::string& key, const std::string& password = "") {
				std::error_code ec;
				auto res = load_public_key_from_string(key, password, ec);
				error::throw_if_error(ec);
				return res;
			}

			/**
			 * \brief Load a private key from a string.
			 *
			 * \param key		String containing a private key as pem
			 * \param pw		Password used to decrypt key (leave empty if not encrypted)
			 * \throw			rsa_exception if an error occurred
			 */
			inline std::string load_private_key_from_string(const std::string& key, const std::string& password = "") {
				std::error_code ec;
				auto res = load_private_key_from_string(key, password, ec);
				error::throw_if_error(ec);
				return res;
			}
		} // namespace helper

		/**
		* \brief Various cryptographic algorithms when working with JWT
		*
		* JWT (JSON Web Tokens) signatures are typically used as the payload for a JWS (JSON Web Signature) or
		* JWE (JSON Web Encryption). Both of these use various cryptographic as specified by
		* [RFC7518](https://tools.ietf.org/html/rfc7518) and are exposed through the a [JOSE
		* Header](https://tools.ietf.org/html/rfc7515#section-4) which points to one of the JWA (JSON Web
		* Algorithms)(https://tools.ietf.org/html/rfc7518#section-3.1)
		*/
		namespace algorithm {
			/**
			 * \brief Base class for HMAC family of algorithms
			 */
			struct hmacsha {
				/**
				 * Construct new hmac algorithm
				 * \param key Key to use for HMAC
				 * \param md Pointer to hash function
				 * \param name Name of the algorithm
				 */
				hmacsha(std::string key, ALG_ID hash_alg, std::string name)
					: secret(std::move(key)), hash_alg(hash_alg), alg_name(std::move(name)) {}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return HMAC signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();

					struct HmacSecretBlob {
						BLOBHEADER header;
						DWORD hmacSecretSize;
						BYTE hmacSecret[1];
					};

					std::vector<BYTE> blobData(
						std::max(offsetof(HmacSecretBlob, hmacSecret) + secret.size(), sizeof(HmacSecretBlob)));
					HmacSecretBlob* hmacSecretBlob = reinterpret_cast<HmacSecretBlob*>(blobData.data());
					hmacSecretBlob->header.bType = PLAINTEXTKEYBLOB;
					hmacSecretBlob->header.bVersion = CUR_BLOB_VERSION;
					hmacSecretBlob->header.reserved = 0;
					hmacSecretBlob->header.aiKeyAlg = CALG_RC2;
					hmacSecretBlob->hmacSecretSize = secret.size();
					memcpy(hmacSecretBlob->hmacSecret, secret.data(), secret.size());

					CCryptContext context;
					if (!CryptAcquireContext(&context, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}

					CCryptKey key;
					if (!CryptImportKey(context.get(), blobData.data(), blobData.size(), 0, CRYPT_IPSEC_HMAC_KEY,
										&key)) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					CCryptHash hash;
					if (!CryptCreateHash(context.get(), CALG_HMAC, key.get(), 0, &hash)) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					HMAC_INFO hmacInfo = {};
					hmacInfo.HashAlgid = hash_alg;

					if (!CryptSetHashParam(hash.get(), HP_HMAC_INFO, reinterpret_cast<BYTE*>(&hmacInfo), 0)) {
						ec = error::signature_generation_error::hmac_failed;
						return {};
					}

					std::string res;
					if (!hash.computeHash(data, res)) {
						ec = error::signature_generation_error::hmac_failed;
						return {};
					}

					return res;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with details about failure.
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();
					auto res = sign(data, ec);
					if (ec) return;

					bool matched = true;
					for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
						if (res[i] != signature[i]) matched = false;
					if (res.size() != signature.size()) matched = false;
					if (!matched) {
						ec = error::signature_verification_error::invalid_signature;
						return;
					}
				}

				/**
				 * Returns the algorithm name provided to the constructor
				 * \return algorithm's name
				 */
				std::string name() const { return alg_name; }

			private:
				/// HMAC secrect
				const std::string secret;
				/// HMAC hash generator
				const ALG_ID hash_alg;
				/// algorithm's name
				const std::string alg_name;
			};

			/**
			 * \brief Base class for RSA family of algorithms
			 */
			struct rsa {
				/**
				 * Construct new rsa algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 * \param md Pointer to hash function
				 * \param name Name of the algorithm
				 */
				rsa(const std::string& public_key, const std::string& private_key,
					const std::string& public_key_password, const std::string& private_key_password, ALG_ID hash_alg,
					std::string name)
					: hash_alg(hash_alg), alg_name(std::move(name)) {
					if (!private_key.empty()) {
						pkey = helper::load_private_key_from_string(private_key, private_key_password);
					} else if (!public_key.empty()) {
						pkey = helper::load_public_key_from_string(public_key, public_key_password);
					} else {
						throw new rsa_exception(error::rsa_error::no_key_provided);
					}
				}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return RSA signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();

					CCryptContext context;
					if (!CryptAcquireContext(&context, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
											 CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}

					CCryptKey key;
					if (!CryptImportKey(context.get(), reinterpret_cast<const BYTE*>(pkey.data()), pkey.size(), 0, NULL,
										&key)) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					CCryptHash hash;
					if (!CryptCreateHash(context.get(), hash_alg, NULL, 0, &hash)) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					if (!CryptHashData(hash.get(), reinterpret_cast<const BYTE*>(data.data()), data.size(), 0)) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					DWORD cbSignature = 0;
					if (!CryptSignHash(hash.get(), AT_KEYEXCHANGE, NULL, 0, NULL, &cbSignature)) {
						ec = error::signature_generation_error::signupdate_failed;
						return {};
					}

					std::string signature(cbSignature, '\0');
					if (!CryptSignHash(hash.get(), AT_KEYEXCHANGE, NULL, 0, reinterpret_cast<BYTE*>(&signature[0]),
									   &cbSignature)) {
						ec = error::signature_generation_error::signfinal_failed;
						return {};
					}

					return signature;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with details on failure
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();

					CCryptContext context;
					if (!CryptAcquireContext(&context, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
											 CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
						ec = error::signature_verification_error::create_context_failed;
						return;
					}

					CCryptKey key;
					if (!CryptImportKey(context.get(), reinterpret_cast<const BYTE*>(pkey.data()), pkey.size(), 0, NULL,
										&key)) {
						ec = error::signature_generation_error::signinit_failed;
						return;
					}

					CCryptHash hash;
					if (!CryptCreateHash(context.get(), hash_alg, NULL, 0, &hash)) {
						ec = error::signature_verification_error::verifyinit_failed;
						return;
					}

					if (!CryptHashData(hash.get(), reinterpret_cast<const BYTE*>(data.data()), data.size(), 0)) {
						ec = error::signature_verification_error::verifyupdate_failed;
						return;
					}

					if (!CryptVerifySignature(hash.get(), reinterpret_cast<const BYTE*>(signature.data()),
											  signature.size(), key.get(), NULL, 0)) {
						ec = error::signature_verification_error::verifyfinal_failed;
						return;
					}
				}

				/**
				 * Returns the algorithm name provided to the constructor
				 * \return algorithm's name
				 */
				std::string name() const { return alg_name; }

			private:
				/// Keys
				std::string pkey;
				/// Hash generator
				ALG_ID hash_alg;
				/// algorithm's name
				const std::string alg_name;
			};

			/**
			* HS256 algorithm
			*/
			struct hs256 : public hmacsha {
				/**
				 * Construct new instance of algorithm
				 * \param key HMAC signing key
				 */
				explicit hs256(std::string key) : hmacsha(std::move(key), CALG_SHA_256, "HS256") {}
			};

			/**
			 * HS384 algorithm
			 */
			struct hs384 : public hmacsha {
				/**
				 * Construct new instance of algorithm
				 * \param key HMAC signing key
				 */
				explicit hs384(std::string key) : hmacsha(std::move(key), CALG_SHA_384, "HS384") {}
			};

			/**
			 * HS512 algorithm
			 */
			struct hs512 : public hmacsha {
				/**
				 * Construct new instance of algorithm
				 * \param key HMAC signing key
				 */
				explicit hs512(std::string key) : hmacsha(std::move(key), CALG_SHA_512, "HS512") {}
			};

			/**
			 * RS256 algorithm
			 */
			struct rs256 : public rsa {
				/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
				explicit rs256(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: rsa(public_key, private_key, public_key_password, private_key_password, CALG_SHA_256, "RS256") {}
			};

			/**
			 * RS384 algorithm
			 */
			struct rs384 : public rsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 */
				explicit rs384(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: rsa(public_key, private_key, public_key_password, private_key_password, CALG_SHA_384, "RS384") {}
			};

			/**
			 * RS512 algorithm
			 */
			struct rs512 : public rsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 */
				explicit rs512(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: rsa(public_key, private_key, public_key_password, private_key_password, CALG_SHA_512, "RS512") {}
			};
		} // namespace algorithm
	}	  // namespace crypto
} // namespace jwt

#endif
