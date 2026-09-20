package com.evtimov.doors.data.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.SystemClock
import android.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Listens for the rotating identifier a door controller advertises.
 *
 * The app does not know the beacon key and cannot compute or predict an
 * identifier. All it can do is report what it heard, which is exactly the
 * point: the value is evidence of having been within Bluetooth range, not a
 * secret the phone holds. Malware that extracts everything this app stores
 * still cannot produce a current identifier from somewhere else in the city.
 *
 * Observations are kept with the elapsed-realtime clock rather than wall time,
 * so changing the phone's clock does not make a stale sighting look fresh.
 */
class BeaconScanner(private val context: Context) {

    data class Sighting(val identifier: String, val rssi: Int, val elapsedRealtimeMs: Long)

    private val sightings = ConcurrentHashMap<String, Sighting>()
    private val _latest = MutableStateFlow<Sighting?>(null)
    val latest: StateFlow<Sighting?> = _latest

    private var scanning = false

    private val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val payload = result.scanRecord?.getManufacturerSpecificData(MANUFACTURER_ID)
                ?: return
            if (payload.size < IDENTIFIER_BYTES) return

            val identifier = Base64.encodeToString(
                payload.copyOf(IDENTIFIER_BYTES),
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            )
            val sighting = Sighting(identifier, result.rssi, SystemClock.elapsedRealtime())
            sightings[identifier] = sighting
            _latest.value = sighting
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
        }
    }

    @SuppressLint("MissingPermission")
    fun start() {
        if (scanning) return
        val scanner = bluetoothScanner() ?: return

        val settings = ScanSettings.Builder()
            // Low latency while the unlock screen is open. The scanner is
            // stopped as soon as it is not, because a permanently scanning
            // app is both a battery problem and a privacy one.
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()

        val filter = ScanFilter.Builder()
            .setManufacturerData(MANUFACTURER_ID, byteArrayOf(), byteArrayOf())
            .build()

        runCatching { scanner.startScan(listOf(filter), settings, callback) }
            .onSuccess { scanning = true }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        if (!scanning) return
        runCatching { bluetoothScanner()?.stopScan(callback) }
        scanning = false
    }

    /**
     * The freshest identifier heard inside [maxAgeMs], or null.
     *
     * The server decides what counts as fresh; this is the client-side filter
     * that keeps the app from sending something it already knows is too old.
     */
    fun freshest(maxAgeMs: Long = MAX_AGE_MS): String? {
        val now = SystemClock.elapsedRealtime()
        return sightings.values
            .filter { now - it.elapsedRealtimeMs <= maxAgeMs }
            .maxByOrNull { it.elapsedRealtimeMs }
            ?.identifier
    }

    fun clear() = sightings.clear()

    private fun bluetoothScanner() =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
            ?.adapter
            ?.takeIf { it.isEnabled }
            ?.bluetoothLeScanner

    companion object {
        /** 0xFFFF: "no company assigned", the correct id for a private protocol. */
        const val MANUFACTURER_ID = 0xFFFF
        const val IDENTIFIER_BYTES = 16
        const val MAX_AGE_MS = 55_000L   // just inside the server's 60 second window
    }
}
