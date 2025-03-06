#pragma once

#include <mbedtls/md.h>
#include <stdint.h>

// TOTP parameters
#define TOTP_DIGITS 6				   // 6-digit OTP
#define TOTP_TIME_STEP 30			   // 30-second time window
#define TOTP_HASH_ALGO MBEDTLS_MD_SHA1 // SHA1 (default for TOTP)

// Compute HMAC-SHA1 using mbedTLS (returns 1 on success, 0 on failure)
static inline int hmac_sha1(const uint8_t* key, size_t key_len,
	const uint8_t* msg, size_t msg_len, uint8_t* output)
{
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t* md_info;

	mbedtls_md_init(&ctx);
	md_info = mbedtls_md_info_from_type(TOTP_HASH_ALGO);
	if (md_info == NULL)
	{
		mbedtls_md_free(&ctx);
		return 0;
	}

	if (mbedtls_md_setup(&ctx, md_info, 1) != 0)
	{
		mbedtls_md_free(&ctx);
		return 0;
	}

	int result = (mbedtls_md_hmac_starts(&ctx, key, key_len) == 0 &&
					 mbedtls_md_hmac_update(&ctx, msg, msg_len) == 0 &&
					 mbedtls_md_hmac_finish(&ctx, output) == 0)
					 ? 1
					 : 0;

	mbedtls_md_free(&ctx);
	return result;
}

// Extract 6-digit OTP using dynamic truncation
static inline uint32_t truncate_hmac(const uint8_t* hmac_result)
{
	int offset = hmac_result[19] & 0x0F; // Last nibble as offset
	uint32_t binary =
		((hmac_result[offset] & 0x7F) << 24) |
		((hmac_result[offset + 1] & 0xFF) << 16) |
		((hmac_result[offset + 2] & 0xFF) << 8) |
		(hmac_result[offset + 3] & 0xFF);

	return binary % 1000000; // Modulo for 6-digit OTP
}

// Generate TOTP using the given secret key (returns -1 if HMAC fails)
int generate_totp(const uint8_t* secret, size_t secret_len, uint64_t timestamp)
{
	uint8_t counter_bytes[8];
	uint8_t hmac_result[20]; // SHA1 produces a 20-byte hash

	uint64_t counter = timestamp / TOTP_TIME_STEP; // Time step counter
	counter_bytes[0] = (counter >> 56) & 0xFF;
	counter_bytes[1] = (counter >> 48) & 0xFF;
	counter_bytes[2] = (counter >> 40) & 0xFF;
	counter_bytes[3] = (counter >> 32) & 0xFF;
	counter_bytes[4] = (counter >> 24) & 0xFF;
	counter_bytes[5] = (counter >> 16) & 0xFF;
	counter_bytes[6] = (counter >> 8) & 0xFF;
	counter_bytes[7] = (counter) & 0xFF;

	// Compute HMAC-SHA1 of counter using the secret key
	if (!hmac_sha1(secret, secret_len, counter_bytes, sizeof(counter_bytes), hmac_result))
	{
		return 0; // HMAC computation failed
	}

	// Extract OTP from HMAC result
	return (int)truncate_hmac(hmac_result);
}