package com.evtimov.doors.di

import android.content.Context
import com.evtimov.doors.data.DoorsRepository
import com.evtimov.doors.data.PlayIntegrityProvider
import com.evtimov.doors.data.api.AcsApi
import com.evtimov.doors.data.api.ApiClient
import com.evtimov.doors.data.ble.BeaconScanner
import com.evtimov.doors.data.local.SettingsStore
import com.evtimov.doors.data.local.TokenStore
import kotlinx.coroutines.flow.MutableSharedFlow

/**
 * Manual dependency wiring.
 *
 * A graph this small does not need an annotation processor. Everything is
 * constructed once, in one readable place, and the build has one fewer moving
 * part that can fail in ways unrelated to the app.
 */
object ServiceLocator {

    lateinit var tokenStore: TokenStore
        private set
    lateinit var settingsStore: SettingsStore
        private set
    lateinit var beaconScanner: BeaconScanner
        private set
    lateinit var repository: DoorsRepository
        private set
    lateinit var api: AcsApi
        private set

    /** Emits when the server has ended the session and the UI must react. */
    val sessionLost = MutableSharedFlow<Unit>(extraBufferCapacity = 1)

    fun initialise(context: Context) {
        val applicationContext = context.applicationContext

        tokenStore = TokenStore(applicationContext)
        settingsStore = SettingsStore(applicationContext)
        beaconScanner = BeaconScanner(applicationContext)

        api = ApiClient.create(tokenStore) { sessionLost.tryEmit(Unit) }
        repository = DoorsRepository(
            api = api,
            tokens = tokenStore,
            scanner = beaconScanner,
            integrity = PlayIntegrityProvider(applicationContext),
        )
    }
}
