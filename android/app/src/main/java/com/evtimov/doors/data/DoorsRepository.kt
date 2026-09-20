package com.evtimov.doors.data

import android.util.Base64
import com.evtimov.doors.data.api.AcsApi
import com.evtimov.doors.data.api.ApiErrorBody
import com.evtimov.doors.data.api.EnrollChallengeRequest
import com.evtimov.doors.data.api.EnrollRequest
import com.evtimov.doors.data.api.UnlockRequest
import com.evtimov.doors.data.ble.BeaconScanner
import com.evtimov.doors.data.crypto.KeystoreManager
import com.evtimov.doors.data.local.TokenStore
import com.evtimov.doors.domain.Door
import com.evtimov.doors.domain.AccessRecord
import com.evtimov.doors.domain.UnlockResult
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import retrofit2.HttpException

class DoorsRepository(
    private val api: AcsApi,
    private val tokens: TokenStore,
    private val scanner: BeaconScanner,
    private val integrity: PlayIntegrityProvider,
) {

    private val json = Json { ignoreUnknownKeys = true }

    val isEnrolled: Boolean get() = tokens.isEnrolled

    /**
     * Enrolment, in the order the server expects.
     *
     * 1. ask for an attestation challenge
     * 2. generate the identity key in the Keystore *over that challenge*
     * 3. collect a Play Integrity token for the same challenge
     * 4. post the certificate chain and the token together
     *
     * The challenge is what ties the chain to this enrolment. Generating the
     * key first and asking for a challenge afterwards would produce a chain
     * that could be replayed onto any number of enrolments.
     */
    suspend fun enroll(code: String, label: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val challenge = api.enrollChallenge(EnrollChallengeRequest(code))
            val challengeBytes = Base64.decode(challenge.challenge, Base64.DEFAULT)

            val key = KeystoreManager.generate(challengeBytes)
            val integrityToken = integrity.tokenFor(challengeBytes)

            val response = api.enroll(
                EnrollRequest(
                    enrollmentCode = code,
                    label = label,
                    devicePublicKey = Base64.encodeToString(
                        key.publicKeyDer.takeLast(32).toByteArray(), Base64.NO_WRAP,
                    ),
                    attestationChain = key.certificateChainPem,
                    playIntegrityToken = integrityToken,
                    challenge = challenge.challenge,
                    appVersion = com.evtimov.doors.BuildConfig.VERSION_NAME,
                )
            )

            tokens.deviceId = response.deviceId
            tokens.savePair(response.accessToken, response.refreshToken)
        }.onFailure {
            // A half-finished enrolment must not leave a key behind that the
            // server has never seen.
            KeystoreManager.deleteKey()
        }
    }

    suspend fun doors(): Result<List<Door>> = withContext(Dispatchers.IO) {
        runCatching {
            api.doors().doors.map { dto ->
                Door(
                    id = dto.id,
                    code = dto.code,
                    name = dto.name,
                    location = dto.location,
                    unlockSeconds = dto.unlockSeconds,
                    controllerOnline = dto.controllerOnline,
                    window = "${dto.windowStart.take(5)}–${dto.windowEnd.take(5)} ${dto.timeZone}",
                    nearby = scanner.freshest() != null,
                )
            }
        }
    }

    suspend fun history(): Result<List<AccessRecord>> = withContext(Dispatchers.IO) {
        runCatching {
            api.accessHistory().records.map {
                AccessRecord(it.seq, it.occurredAt, it.eventType, it.outcome, it.doorId)
            }
        }
    }

    /**
     * Unlock.
     *
     * The proximity identifier is read here rather than being passed in, so
     * there is no path through the app that sends a value the scanner did not
     * actually hear inside the freshness window.
     */
    suspend fun unlock(doorId: String): UnlockResult = withContext(Dispatchers.IO) {
        val beacon = scanner.freshest() ?: return@withContext UnlockResult.NotPresent

        try {
            api.unlock(doorId, UnlockRequest(beacon, UUID.randomUUID().toString()))
            UnlockResult.Opened(0)
        } catch (error: HttpException) {
            when (error.code()) {
                401 -> UnlockResult.SessionLost
                429 -> UnlockResult.RateLimited
                403 -> when (errorCode(error)) {
                    "not_present" -> UnlockResult.NotPresent
                    "controller_offline" -> UnlockResult.ControllerOffline
                    "failed" -> UnlockResult.Failed
                    else -> UnlockResult.Denied
                }
                else -> UnlockResult.Failed
            }
        } catch (_: IOException) {
            UnlockResult.Offline
        }
    }

    suspend fun signOut() = withContext(Dispatchers.IO) {
        runCatching {
            api.logout(com.evtimov.doors.data.api.LogoutRequest(tokens.refreshToken))
        }
        tokens.clearSession()
    }

    suspend fun forgetThisDevice() = withContext(Dispatchers.IO) {
        signOut()
        KeystoreManager.deleteKey()
        tokens.clearEverything()
    }

    private fun errorCode(error: HttpException): String {
        val body = error.response()?.errorBody()?.string() ?: return "denied"
        return runCatching {
            // The API nests the code under "detail" for handled errors.
            val root = json.parseToJsonElement(body)
            val detail = root.jsonObjectOrNull()?.get("detail")
            when {
                detail != null -> json.decodeFromString(ApiErrorBody.serializer(), detail.toString()).error
                else -> json.decodeFromString(ApiErrorBody.serializer(), body).error
            }
        }.getOrDefault("denied")
    }

    private fun kotlinx.serialization.json.JsonElement.jsonObjectOrNull() =
        this as? kotlinx.serialization.json.JsonObject
}
