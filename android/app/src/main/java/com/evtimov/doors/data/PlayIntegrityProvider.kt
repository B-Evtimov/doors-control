package com.evtimov.doors.data

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Play Integrity.
 *
 * Answers a different question from key attestation. Key attestation says the
 * private key is in secure hardware; Play Integrity says the app asking is the
 * build that was published, unmodified, on a device that passes basic
 * integrity. A repackaged APK with a debugger attached can hold a perfectly
 * attested key.
 *
 * The nonce is the SHA-256 of the same attestation challenge the key was
 * generated over, which binds the two statements to one enrolment. A verdict
 * obtained separately cannot be pasted into someone else's request.
 *
 * If the Play services are unavailable the call returns an empty string
 * rather than throwing. The server decides what an absent verdict means -
 * `ACS_ATTESTATION_MODE=strict` refuses it - and that decision belongs on the
 * server, not in code an attacker controls.
 */
class PlayIntegrityProvider(private val context: Context) {

    suspend fun tokenFor(challenge: ByteArray): String =
        suspendCancellableCoroutine { continuation ->
            val nonce = Base64.encodeToString(
                MessageDigest.getInstance("SHA-256").digest(challenge),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )

            runCatching {
                IntegrityManagerFactory.create(context)
                    .requestIntegrityToken(
                        IntegrityTokenRequest.builder().setNonce(nonce).build()
                    )
                    .addOnSuccessListener { response ->
                        if (continuation.isActive) continuation.resume(response.token())
                    }
                    .addOnFailureListener {
                        if (continuation.isActive) continuation.resume("")
                    }
            }.onFailure {
                if (continuation.isActive) continuation.resume("")
            }
        }
}
