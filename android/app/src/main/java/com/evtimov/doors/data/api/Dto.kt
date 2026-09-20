package com.evtimov.doors.data.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class EnrollChallengeRequest(
    @SerialName("enrollment_code") val enrollmentCode: String,
)

@Serializable
data class EnrollChallengeResponse(
    val challenge: String,
    @SerialName("expires_in") val expiresIn: Int,
)

@Serializable
data class EnrollRequest(
    @SerialName("enrollment_code") val enrollmentCode: String,
    val label: String,
    @SerialName("device_public_key") val devicePublicKey: String,
    @SerialName("attestation_chain") val attestationChain: List<String>,
    @SerialName("play_integrity_token") val playIntegrityToken: String,
    val challenge: String,
    val platform: String = "android",
    @SerialName("app_version") val appVersion: String? = null,
)

@Serializable
data class EnrollResponse(
    @SerialName("device_id") val deviceId: String,
    @SerialName("attestation_status") val attestationStatus: String,
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String,
    @SerialName("expires_in") val expiresIn: Int,
)

@Serializable
data class LoginRequest(
    val username: String,
    val password: String,
    @SerialName("device_id") val deviceId: String,
)

@Serializable
data class TokenPair(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String,
    @SerialName("token_type") val tokenType: String = "Bearer",
    @SerialName("expires_in") val expiresIn: Int,
)

@Serializable
data class RefreshRequest(
    @SerialName("refresh_token") val refreshToken: String,
)

@Serializable
data class LogoutRequest(
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("all_devices") val allDevices: Boolean = false,
)

@Serializable
data class DoorDto(
    val id: String,
    val code: String,
    val name: String,
    val location: String? = null,
    @SerialName("unlock_seconds") val unlockSeconds: Int,
    @SerialName("controller_online") val controllerOnline: Boolean,
    @SerialName("window_start") val windowStart: String,
    @SerialName("window_end") val windowEnd: String,
    @SerialName("weekday_mask") val weekdayMask: Int,
    @SerialName("time_zone") val timeZone: String,
)

@Serializable
data class DoorListResponse(
    val doors: List<DoorDto>,
    @SerialName("server_time") val serverTime: String,
)

@Serializable
data class UnlockRequest(
    @SerialName("proximity_beacon_id") val proximityBeaconId: String,
    @SerialName("client_request_id") val clientRequestId: String? = null,
)

@Serializable
data class UnlockResponse(
    val result: String,
    @SerialName("door_id") val doorId: String,
    @SerialName("command_id") val commandId: String,
    @SerialName("opened_for_ms") val openedForMs: Int,
    @SerialName("proximity_age_seconds") val proximityAgeSeconds: Int,
)

@Serializable
data class AccessRecordDto(
    val seq: Long,
    @SerialName("occurred_at") val occurredAt: String,
    @SerialName("event_type") val eventType: String,
    val outcome: String,
    @SerialName("door_id") val doorId: String? = null,
)

@Serializable
data class AccessHistoryResponse(val records: List<AccessRecordDto>)

/** The API answers every failure with this one shape. */
@Serializable
data class ApiErrorBody(val error: String)
