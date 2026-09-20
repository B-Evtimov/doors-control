package com.evtimov.doors.data.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate

/**
 * The phone's identity key.
 *
 * Generated inside the Android Keystore, which means the private key material
 * never enters this process's memory and cannot be read out by anything
 * running on the device - including this app. Everything here works with a
 * handle; the signing happens in the TEE, or in StrongBox on hardware that
 * has it.
 *
 * Three properties are set deliberately:
 *
 *  - `setUserAuthenticationRequired(true)` with a short validity window. The
 *    key refuses to sign until the user has authenticated, so a phone lying
 *    unlocked-but-idle on a table does not open doors.
 *  - `setAttestationChallenge(...)` with a challenge the server issued. What
 *    comes back is a certificate chain that says, signed by Google, that this
 *    key really is in secure hardware on a device with a locked bootloader.
 *    Without the server's challenge in it, a chain captured from any device
 *    would be replayable.
 *  - `setInvalidatedByBiometricEnrolment(true)`. Adding a new fingerprint
 *    destroys the key, so an attacker who can add a fingerprint to a stolen
 *    unlocked phone gets a key that no longer works rather than one that
 *    still opens doors.
 */
object KeystoreManager {

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "acs.device.identity.v1"
    private const val AUTH_VALIDITY_SECONDS = 30

    data class GeneratedKey(
        val publicKeyDer: ByteArray,
        val certificateChainPem: List<String>,
        val securityLevel: String,
    )

    fun hasKey(): Boolean = keystore().containsAlias(ALIAS)

    fun deleteKey() {
        runCatching { keystore().deleteEntry(ALIAS) }
    }

    /**
     * Create the identity key over a server-issued attestation challenge.
     *
     * StrongBox is requested first and the code falls back to the TEE if the
     * device has no secure element. Both are acceptable; the server is told
     * which one it got and decides.
     */
    fun generate(attestationChallenge: ByteArray): GeneratedKey {
        deleteKey()

        val built = runCatching { generateInternal(attestationChallenge, strongBox = true) }
            .recoverCatching { error ->
                if (error is StrongBoxUnavailableException) {
                    generateInternal(attestationChallenge, strongBox = false)
                } else {
                    throw error
                }
            }
            .getOrThrow()

        return built
    }

    private fun generateInternal(challenge: ByteArray, strongBox: Boolean): GeneratedKey {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)

        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            setAttestationChallenge(challenge)

            setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(
                    AUTH_VALIDITY_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
            }

            setInvalidatedByBiometricEnrollment(true)

            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(true)
            }
        }.build()

        generator.initialize(spec)
        generator.generateKeyPair()

        val chain = keystore().getCertificateChain(ALIAS) ?: emptyArray()
        return GeneratedKey(
            publicKeyDer = chain.first().publicKey.encoded,
            certificateChainPem = chain.map(::toPem),
            securityLevel = if (strongBox) "strongbox" else "trusted_environment",
        )
    }

    /**
     * Sign with the identity key.
     *
     * Throws [android.security.keystore.UserNotAuthenticatedException] if the
     * user has not authenticated inside the validity window - which is the
     * mechanism, not an error to work around.
     */
    fun sign(message: ByteArray): ByteArray {
        val entry = keystore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: error("identity key is missing; the device must enrol again")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey as PrivateKey)
            update(message)
            sign()
        }
    }

    private fun keystore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun toPem(certificate: Certificate): String {
        val encoded = android.util.Base64.encodeToString(
            certificate.encoded, android.util.Base64.NO_WRAP,
        )
        return buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            encoded.chunked(64).forEach { append(it).append('\n') }
            append("-----END CERTIFICATE-----\n")
        }
    }
}
