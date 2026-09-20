package com.evtimov.doors.domain

/** A door as the UI needs it. */
data class Door(
    val id: String,
    val code: String,
    val name: String,
    val location: String?,
    val unlockSeconds: Int,
    val controllerOnline: Boolean,
    val window: String,
    val nearby: Boolean,
)

data class AccessRecord(
    val seq: Long,
    val occurredAt: String,
    val eventType: String,
    val outcome: String,
    val doorId: String?,
)

/**
 * What the user is told.
 *
 * The server answers with a small fixed set of reasons on purpose: "you have
 * no grant", "you are outside your hours" and "that door does not exist" all
 * arrive as [Denied]. The precise reason is in the audit log, where the
 * operator can see it and the person holding the phone cannot.
 */
sealed interface UnlockResult {
    data class Opened(val openedForMs: Int) : UnlockResult
    data object Denied : UnlockResult
    data object NotPresent : UnlockResult
    data object ControllerOffline : UnlockResult
    data object RateLimited : UnlockResult
    data object Failed : UnlockResult
    data object SessionLost : UnlockResult
    data object Offline : UnlockResult
    data object BiometricRefused : UnlockResult
}
