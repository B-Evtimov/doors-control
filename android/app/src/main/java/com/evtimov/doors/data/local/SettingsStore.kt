package com.evtimov.doors.data.local

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "acs_settings")

/**
 * Settings that are not worth protecting: a display name, a preference for
 * haptics. Nothing here is a credential, which is why it is not encrypted -
 * pretending otherwise would just be noise.
 */
class SettingsStore(private val context: Context) {

    val deviceLabel: Flow<String> =
        context.dataStore.data.map { it[KEY_LABEL] ?: "" }

    val hapticsEnabled: Flow<Boolean> =
        context.dataStore.data.map { it[KEY_HAPTICS] ?: true }

    val keepScreenOnWhileUnlocking: Flow<Boolean> =
        context.dataStore.data.map { it[KEY_KEEP_SCREEN] ?: true }

    suspend fun setDeviceLabel(value: String) {
        context.dataStore.edit { it[KEY_LABEL] = value }
    }

    suspend fun setHaptics(value: Boolean) {
        context.dataStore.edit { it[KEY_HAPTICS] = value }
    }

    suspend fun setKeepScreenOn(value: Boolean) {
        context.dataStore.edit { it[KEY_KEEP_SCREEN] = value }
    }

    suspend fun clear() {
        context.dataStore.edit { it.clear() }
    }

    private companion object {
        val KEY_LABEL = stringPreferencesKey("device_label")
        val KEY_HAPTICS = booleanPreferencesKey("haptics")
        val KEY_KEEP_SCREEN = booleanPreferencesKey("keep_screen_on")
    }
}
