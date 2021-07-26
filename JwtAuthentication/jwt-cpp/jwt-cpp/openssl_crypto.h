#ifndef JWT_CPP_OPENSSL_CRYPTO_H
#define JWT_CPP_OPENSSL_CRYPTO_H

#include <iostream>
#include <memory>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include "error.h"

// If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OPENSSL10
#endif

// If openssl version less than 1.1.1
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define OPENSSL110
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define OPENSSL10
#define OPENSSL110
#endif

namespace jwt {
	namespace crypto {
		namespace helper {

			/**
			 * \brief Extract the public key of a pem certificate
			 *
			 * \param certstr	String containing the certificate encoded as pem
			 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
			 * \param ec		error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw,
														std::error_code& ec) {
				ec.clear();

#if OPENSSL_VERSION_NUMBER <= 0x10100003L
				std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(
					BIO_new_mem_buf(const_cast<char*>(certstr.data()), static_cast<int>(certstr.size())), BIO_free_all);
#else
				std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(
					BIO_new_mem_buf(certstr.data(), static_cast<int>(certstr.size())), BIO_free_all);
#endif
				std::unique_ptr<BIO, decltype(&BIO_free_all)> keybio(BIO_new(BIO_s_mem()), BIO_free_all);
				if (!certbio || !keybio) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				std::unique_ptr<X509, decltype(&X509_free)> cert(
					PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
				if (!cert) {
					ec = error::rsa_error::cert_load_failed;
					return {};
				}
				std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
				if (!key) {
					ec = error::rsa_error::get_key_failed;
					return {};
				}
				if (PEM_write_bio_PUBKEY(keybio.get(), key.get()) == 0) {
					ec = error::rsa_error::write_key_failed;
					return {};
				}

				char* ptr = nullptr;
				size_t len = static_cast<size_t>(BIO_get_mem_data(keybio.get(), &ptr));

				if (len <= 0 || ptr == nullptr) {
					ec = error::rsa_error::convert_to_pem_failed;
					return {};
				}

				return {ptr, len};
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

				auto c_str = reinterpret_cast<const unsigned char*>(decodedStr.c_str());
				std::unique_ptr<X509, decltype(&X509_free)> cert(
					d2i_X509(NULL, &c_str, static_cast<int>(decodedStr.size())), X509_free);
				std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new(BIO_s_mem()), BIO_free_all);
				if (!cert || !certbio) {
					ec = error::rsa_error::create_mem_bio_failed;
					return {};
				}

				if (!PEM_write_bio_X509(certbio.get(), cert.get())) {
					ec = error::rsa_error::write_cert_failed;
					return {};
				}

				char* ptr = nullptr;
				const auto len = BIO_get_mem_data(certbio.get(), &ptr);
				if (len <= 0 || ptr == nullptr) {
					ec = error::rsa_error::convert_to_pem_failed;
					return {};
				}

				return {ptr, static_cast<size_t>(len)};
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
			inline std::shared_ptr<EVP_PKEY>
			load_public_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
				ec.clear();
				std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
				if (!pubkey_bio) {
					ec = error::rsa_error::create_mem_bio_failed;
					return nullptr;
				}
				if (key.find("-----BEGIN CERTIFICATE-----") == 0) {
					auto epkey = helper::extract_pubkey_from_cert(key, password, ec);
					if (ec) return nullptr;
					const int len = static_cast<int>(epkey.size());
					if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len) {
						ec = error::rsa_error::load_key_bio_write;
						return nullptr;
					}
				} else {
					const int len = static_cast<int>(key.size());
					if (BIO_write(pubkey_bio.get(), key.data(), len) != len) {
						ec = error::rsa_error::load_key_bio_write;
						return nullptr;
					}
				}

				std::shared_ptr<EVP_PKEY> pkey(
					PEM_read_bio_PUBKEY(
						pubkey_bio.get(), nullptr, nullptr,
						(void*)password.data()), // NOLINT(google-readability-casting) requires `const_cast`
					EVP_PKEY_free);
				if (!pkey) {
					ec = error::rsa_error::load_key_bio_read;
					return nullptr;
				}
				return pkey;
			}

			/**
			 * \brief Load a private key from a string.
			 *
			 * \param key		String containing a private key as pem
			 * \param pw		Password used to decrypt key (leave empty if not encrypted)
			 * \param ec		error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::shared_ptr<EVP_PKEY>
			load_private_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
				std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
				if (!privkey_bio) {
					ec = error::rsa_error::create_mem_bio_failed;
					return nullptr;
				}
				const int len = static_cast<int>(key.size());
				if (BIO_write(privkey_bio.get(), key.data(), len) != len) {
					ec = error::rsa_error::load_key_bio_write;
					return nullptr;
				}
				std::shared_ptr<EVP_PKEY> pkey(
					PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())),
					EVP_PKEY_free);
				if (!pkey) {
					ec = error::rsa_error::load_key_bio_read;
					return nullptr;
				}
				return pkey;
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
			inline std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key,
																	 const std::string& password = "") {
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
			inline std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key,
																	  const std::string& password = "") {
				std::error_code ec;
				auto res = load_private_key_from_string(key, password, ec);
				error::throw_if_error(ec);
				return res;
			}

			/**
			 * Convert a OpenSSL BIGNUM to a std::string
			 * \param bn BIGNUM to convert
			 * \return bignum as string
			 */
			inline
#ifdef OPENSSL10
				static std::string
				bn2raw(BIGNUM* bn)
#else
				static std::string
				bn2raw(const BIGNUM* bn)
#endif
			{
				std::string res(BN_num_bytes(bn), '\0');
				BN_bn2bin(bn, (unsigned char*)res.data()); // NOLINT(google-readability-casting) requires `const_cast`
				return res;
			}
			/**
			 * Convert an std::string to a OpenSSL BIGNUM
			 * \param raw String to convert
			 * \return BIGNUM representation
			 */
			inline static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
				return std::unique_ptr<BIGNUM, decltype(&BN_free)>(
					BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()),
							  nullptr),
					BN_free);
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
				hmacsha(std::string key, const EVP_MD* (*md)(), std::string name)
					: secret(std::move(key)), md(md), alg_name(std::move(name)) {}
				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return HMAC signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();
					std::string res(static_cast<size_t>(EVP_MAX_MD_SIZE), '\0');
					auto len = static_cast<unsigned int>(res.size());
					if (HMAC(md(), secret.data(), static_cast<int>(secret.size()),
							 reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()),
							 (unsigned char*)res.data(), // NOLINT(google-readability-casting) requires `const_cast`
							 &len) == nullptr) {
						ec = error::signature_generation_error::hmac_failed;
						return {};
					}
					res.resize(len);
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
				const EVP_MD* (*md)();
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
					const std::string& public_key_password, const std::string& private_key_password,
					const EVP_MD* (*md)(), std::string name)
					: md(md), alg_name(std::move(name)) {
					if (!private_key.empty()) {
						pkey = helper::load_private_key_from_string(private_key, private_key_password);
					} else if (!public_key.empty()) {
						pkey = helper::load_public_key_from_string(public_key, public_key_password);
					} else
						throw rsa_exception(error::rsa_error::no_key_provided);
				}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return RSA signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();
#ifdef OPENSSL10
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
																				   EVP_MD_CTX_destroy);
#else
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
					if (!ctx) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}
					if (!EVP_SignInit(ctx.get(), md())) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					std::string res(EVP_PKEY_size(pkey.get()), '\0');
					unsigned int len = 0;

					if (!EVP_SignUpdate(ctx.get(), data.data(), data.size())) {
						ec = error::signature_generation_error::signupdate_failed;
						return {};
					}
					if (EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get()) == 0) {
						ec = error::signature_generation_error::signfinal_failed;
						return {};
					}

					res.resize(len);
					return res;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with details on failure
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();
#ifdef OPENSSL10
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
																				   EVP_MD_CTX_destroy);
#else
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
					if (!ctx) {
						ec = error::signature_verification_error::create_context_failed;
						return;
					}
					if (!EVP_VerifyInit(ctx.get(), md())) {
						ec = error::signature_verification_error::verifyinit_failed;
						return;
					}
					if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size())) {
						ec = error::signature_verification_error::verifyupdate_failed;
						return;
					}
					auto res = EVP_VerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
											   static_cast<unsigned int>(signature.size()), pkey.get());
					if (res != 1) {
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
				/// OpenSSL structure containing converted keys
				std::shared_ptr<EVP_PKEY> pkey;
				/// Hash generator
				const EVP_MD* (*md)();
				/// algorithm's name
				const std::string alg_name;
			};

			/**
			 * \brief Base class for ECDSA family of algorithms
			 */
			struct ecdsa {
				/**
				 * Construct new ecdsa algorithm
				 * \param public_key ECDSA public key in PEM format
				 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
				 * fail. \param public_key_password Password to decrypt public key pem. \param private_key_password Password
				 * to decrypt private key pem. \param md Pointer to hash function \param name Name of the algorithm
				 */
				ecdsa(const std::string& public_key, const std::string& private_key,
					  const std::string& public_key_password, const std::string& private_key_password,
					  const EVP_MD* (*md)(), std::string name, size_t siglen)
					: md(md), alg_name(std::move(name)), signature_length(siglen) {
					if (!public_key.empty()) {
						std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if (!pubkey_bio) throw ecdsa_exception(error::ecdsa_error::create_mem_bio_failed);
						if (public_key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
							auto epkey = helper::extract_pubkey_from_cert(public_key, public_key_password);
							const int len = static_cast<int>(epkey.size());
							if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len)
								throw ecdsa_exception(error::ecdsa_error::load_key_bio_write);
						} else {
							const int len = static_cast<int>(public_key.size());
							if (BIO_write(pubkey_bio.get(), public_key.data(), len) != len)
								throw ecdsa_exception(error::ecdsa_error::load_key_bio_write);
						}

						pkey.reset(PEM_read_bio_EC_PUBKEY(
									   pubkey_bio.get(), nullptr, nullptr,
									   (void*)public_key_password
										   .c_str()), // NOLINT(google-readability-casting) requires `const_cast`
								   EC_KEY_free);
						if (!pkey) throw ecdsa_exception(error::ecdsa_error::load_key_bio_read);
						size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
						if (keysize != signature_length * 4 && (signature_length != 132 || keysize != 521))
							throw ecdsa_exception(error::ecdsa_error::invalid_key_size);
					}

					if (!private_key.empty()) {
						std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						if (!privkey_bio) throw ecdsa_exception(error::ecdsa_error::create_mem_bio_failed);
						const int len = static_cast<int>(private_key.size());
						if (BIO_write(privkey_bio.get(), private_key.data(), len) != len)
							throw ecdsa_exception(error::ecdsa_error::load_key_bio_write);
						pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr,
															 const_cast<char*>(private_key_password.c_str())),
								   EC_KEY_free);
						if (!pkey) throw ecdsa_exception(error::ecdsa_error::load_key_bio_read);
						size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
						if (keysize != signature_length * 4 && (signature_length != 132 || keysize != 521))
							throw ecdsa_exception(error::ecdsa_error::invalid_key_size);
					}
					if (!pkey) throw ecdsa_exception(error::ecdsa_error::no_key_provided);

					if (EC_KEY_check_key(pkey.get()) == 0) throw ecdsa_exception(error::ecdsa_error::invalid_key);
				}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return ECDSA signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();
					const std::string hash = generate_hash(data, ec);
					if (ec) return {};

					std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
						ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.data()),
									  static_cast<int>(hash.size()), pkey.get()),
						ECDSA_SIG_free);
					if (!sig) {
						ec = error::signature_generation_error::ecdsa_do_sign_failed;
						return {};
					}
#ifdef OPENSSL10

					auto rr = helper::bn2raw(sig->r);
					auto rs = helper::bn2raw(sig->s);
#else
					const BIGNUM* r;
					const BIGNUM* s;
					ECDSA_SIG_get0(sig.get(), &r, &s);
					auto rr = helper::bn2raw(r);
					auto rs = helper::bn2raw(s);
#endif
					if (rr.size() > signature_length / 2 || rs.size() > signature_length / 2)
						throw std::logic_error("bignum size exceeded expected length");
					rr.insert(0, signature_length / 2 - rr.size(), '\0');
					rs.insert(0, signature_length / 2 - rs.size(), '\0');
					return rr + rs;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with details on error
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();
					const std::string hash = generate_hash(data, ec);
					if (ec) return;
					auto r = helper::raw2bn(signature.substr(0, signature.size() / 2));
					auto s = helper::raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
					ECDSA_SIG sig;
					sig.r = r.get();
					sig.s = s.get();

					if (ECDSA_do_verify((const unsigned char*)hash.data(), static_cast<int>(hash.size()), &sig,
										pkey.get()) != 1) {
						ec = error::signature_verification_error::invalid_signature;
						return;
					}
#else
					std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
					if (!sig) {
						ec = error::signature_verification_error::create_context_failed;
						return;
					}

					ECDSA_SIG_set0(sig.get(), r.release(), s.release());

					if (ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.data()),
										static_cast<int>(hash.size()), sig.get(), pkey.get()) != 1) {
						ec = error::signature_verification_error::invalid_signature;
						return;
					}
#endif
				}

				/**
				 * Returns the algorithm name provided to the constructor
				 * \return algorithm's name
				 */
				std::string name() const { return alg_name; }

			private:
				/**
				 * Hash the provided data using the hash function specified in constructor
				 * \param data Data to hash
				 * \return Hash of data
				 */
				std::string generate_hash(const std::string& data, std::error_code& ec) const {
#ifdef OPENSSL10
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
																				   &EVP_MD_CTX_destroy);
#else
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
					if (!ctx) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}
					if (EVP_DigestInit(ctx.get(), md()) == 0) {
						ec = error::signature_generation_error::digestinit_failed;
						return {};
					}
					if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0) {
						ec = error::signature_generation_error::digestupdate_failed;
						return {};
					}
					unsigned int len = 0;
					std::string res(EVP_MD_CTX_size(ctx.get()), '\0');
					if (EVP_DigestFinal(
							ctx.get(),
							(unsigned char*)res.data(), // NOLINT(google-readability-casting) requires `const_cast`
							&len) == 0) {
						ec = error::signature_generation_error::digestfinal_failed;
						return {};
					}
					res.resize(len);
					return res;
				}

				/// OpenSSL struct containing keys
				std::shared_ptr<EVP_PKEY> pkey;
				/// Hash generator function
				const EVP_MD* (*md)();
				/// algorithm's name
				const std::string alg_name;
				/// Length of the resulting signature
				const size_t signature_length;
			};

#ifndef OPENSSL110
			/**
			 * \brief Base class for EdDSA family of algorithms
			 *
			 * https://tools.ietf.org/html/rfc8032
			 *
			 * The EdDSA algorithms were introduced in [OpenSSL v1.1.1](https://www.openssl.org/news/openssl-1.1.1-notes.html),
			 * so these algorithms are only available when building against this version or higher.
			 */
			struct eddsa {
				/**
				 * Construct new eddsa algorithm
				 * \param public_key EdDSA public key in PEM format
				 * \param private_key EdDSA private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 * \param name Name of the algorithm
				 */
				eddsa(const std::string& public_key, const std::string& private_key,
					  const std::string& public_key_password, const std::string& private_key_password, std::string name)
					: alg_name(std::move(name)) {
					if (!private_key.empty()) {
						pkey = helper::load_private_key_from_string(private_key, private_key_password);
					} else if (!public_key.empty()) {
						pkey = helper::load_public_key_from_string(public_key, public_key_password);
					} else
						throw ecdsa_exception(error::ecdsa_error::load_key_bio_read);
				}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return EdDSA signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
					if (!ctx) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}
					if (!EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get())) {
						ec = error::signature_generation_error::signinit_failed;
						return {};
					}

					size_t len = EVP_PKEY_size(pkey.get());
					std::string res(len, '\0');

// LibreSSL is the special kid in the block, as it does not support EVP_DigestSign.
// OpenSSL on the otherhand does not support using EVP_DigestSignUpdate for eddsa, which is why we end up with this
// mess.
#ifdef LIBRESSL_VERSION_NUMBER
					ERR_clear_error();
					if (EVP_DigestSignUpdate(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()),
											 data.size()) != 1) {
						std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
						ec = error::signature_generation_error::signupdate_failed;
						return {};
					}
					if (EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char*>(&res[0]), &len) != 1) {
						ec = error::signature_generation_error::signfinal_failed;
						return {};
					}
#else
					if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(&res[0]), &len,
									   reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
						ec = error::signature_generation_error::signfinal_failed;
						return {};
					}
#endif

					res.resize(len);
					return res;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with details on error
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
					if (!ctx) {
						ec = error::signature_verification_error::create_context_failed;
						return;
					}
					if (!EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get())) {
						ec = error::signature_verification_error::verifyinit_failed;
						return;
					}

// LibreSSL is the special kid in the block, as it does not support EVP_DigestVerify.
// OpenSSL on the otherhand does not support using EVP_DigestVerifyUpdate for eddsa, which is why we end up with this
// mess.
#ifdef LIBRESSL_VERSION_NUMBER
					if (EVP_DigestVerifyUpdate(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()),
											   data.size()) != 1) {
						ec = error::signature_verification_error::verifyupdate_failed;
						return;
					}
					if (EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
											  signature.size()) != 1) {
						ec = error::signature_verification_error::verifyfinal_failed;
						return;
					}
#else
					auto res = EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
												signature.size(), reinterpret_cast<const unsigned char*>(data.data()),
												data.size());
					if (res != 1) {
						ec = error::signature_verification_error::verifyfinal_failed;
						return;
					}
#endif
				}

				/**
				 * Returns the algorithm name provided to the constructor
				 * \return algorithm's name
				 */
				std::string name() const { return alg_name; }

			private:
				/// OpenSSL struct containing keys
				std::shared_ptr<EVP_PKEY> pkey;
				/// algorithm's name
				const std::string alg_name;
			};
#endif

			/**
			 * \brief Base class for PSS-RSA family of algorithms
			 */
			struct pss {
				/**
				 * Construct new pss algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 * \param md Pointer to hash function
				 * \param name Name of the algorithm
				 */
				pss(const std::string& public_key, const std::string& private_key,
					const std::string& public_key_password, const std::string& private_key_password,
					const EVP_MD* (*md)(), std::string name)
					: md(md), alg_name(std::move(name)) {
					if (!private_key.empty()) {
						pkey = helper::load_private_key_from_string(private_key, private_key_password);
					} else if (!public_key.empty()) {
						pkey = helper::load_public_key_from_string(public_key, public_key_password);
					} else
						throw rsa_exception(error::rsa_error::no_key_provided);
				}

				/**
				 * Sign jwt data
				 * \param data The data to sign
				 * \param ec error_code filled with details on error
				 * \return ECDSA signature for the given data
				 */
				std::string sign(const std::string& data, std::error_code& ec) const {
					ec.clear();
					auto hash = this->generate_hash(data, ec);
					if (ec) return {};

					std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
					if (!key) {
						ec = error::signature_generation_error::get_key_failed;
						return {};
					}
					const int size = RSA_size(key.get());

					std::string padded(size, 0x00);
					if (RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(),
													   reinterpret_cast<const unsigned char*>(hash.data()), md(), md(),
													   -1) ==
						0) { // NOLINT(google-readability-casting) requires `const_cast`
						ec = error::signature_generation_error::rsa_padding_failed;
						return {};
					}

					std::string res(size, 0x00);
					if (RSA_private_encrypt(size, reinterpret_cast<const unsigned char*>(padded.data()),
											(unsigned char*)res.data(), key.get(), RSA_NO_PADDING) <
						0) { // NOLINT(google-readability-casting) requires `const_cast`
						ec = error::signature_generation_error::rsa_private_encrypt_failed;
						return {};
					}
					return res;
				}

				/**
				 * Check if signature is valid
				 * \param data The data to check signature against
				 * \param signature Signature provided by the jwt
				 * \param ec Filled with error details
				 */
				void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
					ec.clear();
					auto hash = this->generate_hash(data, ec);
					if (ec) return;

					std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
					if (!key) {
						ec = error::signature_verification_error::get_key_failed;
						return;
					}
					const int size = RSA_size(key.get());

					std::string sig(size, 0x00);
					if (RSA_public_decrypt(
							static_cast<int>(signature.size()),
							reinterpret_cast<const unsigned char*>(signature.data()),
							(unsigned char*)sig.data(), // NOLINT(google-readability-casting) requires `const_cast`
							key.get(), RSA_NO_PADDING) == 0) {
						ec = error::signature_verification_error::invalid_signature;
						return;
					}

					if (RSA_verify_PKCS1_PSS_mgf1(key.get(), reinterpret_cast<const unsigned char*>(hash.data()), md(),
												  md(), reinterpret_cast<const unsigned char*>(sig.data()), -1) == 0) {
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
				/**
				 * Hash the provided data using the hash function specified in constructor
				 * \param data Data to hash
				 * \return Hash of data
				 */
				std::string generate_hash(const std::string& data, std::error_code& ec) const {
#ifdef OPENSSL10
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(),
																				   &EVP_MD_CTX_destroy);
#else
					std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
					if (!ctx) {
						ec = error::signature_generation_error::create_context_failed;
						return {};
					}
					if (EVP_DigestInit(ctx.get(), md()) == 0) {
						ec = error::signature_generation_error::digestinit_failed;
						return {};
					}
					if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0) {
						ec = error::signature_generation_error::digestupdate_failed;
						return {};
					}
					unsigned int len = 0;
					std::string res(EVP_MD_CTX_size(ctx.get()), '\0');
					if (EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) ==
						0) { // NOLINT(google-readability-casting) requires `const_cast`
						ec = error::signature_generation_error::digestfinal_failed;
						return {};
					}
					res.resize(len);
					return res;
				}

				/// OpenSSL structure containing keys
				std::shared_ptr<EVP_PKEY> pkey;
				/// Hash generator function
				const EVP_MD* (*md)();
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
				explicit hs256(std::string key) : hmacsha(std::move(key), EVP_sha256, "HS256") {}
			};

			/**
			 * HS384 algorithm
			 */
			struct hs384 : public hmacsha {
				/**
				 * Construct new instance of algorithm
				 * \param key HMAC signing key
				 */
				explicit hs384(std::string key) : hmacsha(std::move(key), EVP_sha384, "HS384") {}
			};

			/**
			 * HS512 algorithm
			 */
			struct hs512 : public hmacsha {
				/**
				 * Construct new instance of algorithm
				 * \param key HMAC signing key
				 */
				explicit hs512(std::string key) : hmacsha(std::move(key), EVP_sha512, "HS512") {}
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
					: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256") {}
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
					: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384") {}
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
					: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512") {}
			};

			/**
			 * ES256 algorithm
			 */
			struct es256 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key ECDSA public key in PEM format
				 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 */
				explicit es256(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256",
							64) {}
			};

			/**
			 * ES384 algorithm
			 */
			struct es384 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key ECDSA public key in PEM format
				 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 */
				explicit es384(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384",
							96) {}
			};

			/**
			 * ES512 algorithm
			 */
			struct es512 : public ecdsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key ECDSA public key in PEM format
				 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 */
				explicit es512(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512",
							132) {}
			};

#ifndef OPENSSL110
			/**
			 * Ed25519 algorithm
			 *
			 * https://en.wikipedia.org/wiki/EdDSA#Ed25519
			 *
			 * Requires at least OpenSSL 1.1.1.
			 */
			struct ed25519 : public eddsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key Ed25519 public key in PEM format
				 * \param private_key Ed25519 private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 */
				explicit ed25519(const std::string& public_key, const std::string& private_key = "",
								 const std::string& public_key_password = "",
								 const std::string& private_key_password = "")
					: eddsa(public_key, private_key, public_key_password, private_key_password, "EdDSA") {}
			};

			/**
			 * Ed448 algorithm
			 *
			 * https://en.wikipedia.org/wiki/EdDSA#Ed448
			 *
			 * Requires at least OpenSSL 1.1.1.
			 */
			struct ed448 : public eddsa {
				/**
				 * Construct new instance of algorithm
				 * \param public_key Ed448 public key in PEM format
				 * \param private_key Ed448 private key or empty string if not available. If empty, signing will always
				 * fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password
				 * to decrypt private key pem.
				 */
				explicit ed448(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: eddsa(public_key, private_key, public_key_password, private_key_password, "EdDSA") {}
			};
#endif

			/**
			 * PS256 algorithm
			 */
			struct ps256 : public pss {
				/**
				 * Construct new instance of algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 */
				explicit ps256(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256") {}
			};

			/**
			 * PS384 algorithm
			 */
			struct ps384 : public pss {
				/**
				 * Construct new instance of algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 */
				explicit ps384(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384") {}
			};

			/**
			 * PS512 algorithm
			 */
			struct ps512 : public pss {
				/**
				 * Construct new instance of algorithm
				 * \param public_key RSA public key in PEM format
				 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
				 * \param public_key_password Password to decrypt public key pem.
				 * \param private_key_password Password to decrypt private key pem.
				 */
				explicit ps512(const std::string& public_key, const std::string& private_key = "",
							   const std::string& public_key_password = "",
							   const std::string& private_key_password = "")
					: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512") {}
			};

		} // namespace algorithm
	}	  // namespace crypto
} // namespace jwt

#endif
