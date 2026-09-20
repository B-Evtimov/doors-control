package com.evtimov.doors.data.crypto

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * The biometric check in front of every unlock.
 *
 * This is not only a confirmation dialog. The identity key in the Keystore is
 * generated with `setUserAuthenticationRequired(true)` and a 30 second
 * validity window, so a successful prompt is what makes the key usable at all.
 * Someone holding an unlocked phone without the owner's finger or face gets a
 * key that refuses to sign.
 */
class BiometricGate(private val activity: FragmentActivity) {

    enum class Availability { Available, NoHardware, NotEnrolled, TemporarilyUnavailable }

    fun availability(): Availability =
        when (BiometricManager.from(activity).canAuthenticate(ALLOWED)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.Available
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> Availability.NoHardware
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NotEnrolled
            else -> Availability.TemporarilyUnavailable
        }

    suspend fun authenticate(title: String, subtitle: String, cancel: String): Boolean =
        suspendCancellableCoroutine { continuation ->
            val prompt = BiometricPrompt(
                activity,
                androidx.core.content.ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult,
                    ) {
                        if (continuation.isActive) continuation.resume(true)
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (continuation.isActive) continuation.resume(false)
                    }

                    override fun onAuthenticationFailed() {
                        // A single non-matching finger is not a final answer;
                        // the prompt stays up and the user tries again.
                    }
                },
            )

            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText(cancel)
                .setAllowedAuthenticators(ALLOWED)
                .setConfirmationRequired(false)
                .build()

            prompt.authenticate(info)
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }

    private companion object {
        // Class 3 biometrics only. Class 2 cannot gate a Keystore key, which
        // means it would be a dialog and nothing more.
        const val ALLOWED = BiometricManager.Authenticators.BIOMETRIC_STRONG
    }
}
