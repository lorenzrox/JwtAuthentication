#ifndef JWT_CPP_CRYPTO_H
#define JWT_CPP_CRYPTO_H

#if defined(_WIN32) && !defined(JWT_DISABLE_WIN_CAPI)

#include "win_crypto.h"

#define JWT_WIN_CRYPTO

#else

#include "openssl_crypto.h"

#define JWT_OPENSSL_CRYPTO

#endif

namespace jwt {
	namespace crypto {
		/**
		 * \brief A collection for working with certificates
		 *
		 * These _helpers_ are usefully when working with certificates OpenSSL APIs.
		 * For example, when dealing with JWKS (JSON Web Key Set)[https://tools.ietf.org/html/rfc7517]
		 * you maybe need to extract the modulus and exponent of an RSA Public Key.
		 */
		namespace helper {
			/**
			 * \brief Extract the public key of a pem certificate
			 *
			 * \param certstr	String containing the certificate encoded as pem
			 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
			 * \throw			rsa_exception if an error occurred
			 */
			inline std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "") {
				std::error_code ec;
				auto res = extract_pubkey_from_cert(certstr, pw, ec);
				error::throw_if_error(ec);
				return res;
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
			 * \throw						rsa_exception if an error occurred
			 */
			template<typename Decode>
			std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, Decode decode) {
				std::error_code ec;
				auto res = convert_base64_der_to_pem(cert_base64_der_str, std::move(decode), ec);
				error::throw_if_error(ec);
				return res;
			}

#ifndef JWT_DISABLE_BASE64
			/**
			 * \brief Convert the certificate provided as base64 DER to PEM.
			 *
			 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
			 * (here)[https://tools.ietf.org/html/rfc7517#section-4.7]
			 *
			 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
			 * \param ec					error_code for error_detection (gets cleared if no error occures)
			 */
			inline std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, std::error_code& ec) {
				auto decode = [](const std::string& token) {
					return base::decode<alphabet::base64>(base::pad<alphabet::base64>(token));
				};
				return convert_base64_der_to_pem(cert_base64_der_str, std::move(decode), ec);
			}

			/**
			 * \brief Convert the certificate provided as base64 DER to PEM.
			 *
			 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
			 * (here)[https://tools.ietf.org/html/rfc7517#section-4.7]
			 *
			 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
			 * \throw						rsa_exception if an error occurred
			 */
			inline std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str) {
				std::error_code ec;
				auto res = convert_base64_der_to_pem(cert_base64_der_str, ec);
				error::throw_if_error(ec);
				return res;
			}
#endif
		} // namespace helper

		namespace algorithm {
			/**
			 * \brief "none" algorithm.
			 *
			 * Returns and empty signature and checks if the given signature is empty.
			 */
			struct none {
				/**
				 * \brief Return an empty string
				 */
				std::string sign(const std::string& /*unused*/, std::error_code& ec) const {
					ec.clear();
					return {};
				}

				/**
				 * \brief Check if the given signature is empty.
				 *
				 * JWT's with "none" algorithm should not contain a signature.
				 * \param signature Signature data to verify
				 * \param ec		error_code filled with details about the error
				 */
				void verify(const std::string& /*unused*/, const std::string& signature, std::error_code& ec) const {
					ec.clear();
					if (!signature.empty()) { ec = error::signature_verification_error::invalid_signature; }
				}

				/// Get algorithm name
				std::string name() const { return "none"; }
			};
		} // namespace algorithm
	}	  // namespace crypto
} // namespace jwt

#endif
