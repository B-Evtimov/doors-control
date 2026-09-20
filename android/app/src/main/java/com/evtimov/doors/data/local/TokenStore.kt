package com.evtimov.doors.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Where the opaque tokens live.
 *
 * `EncryptedSharedPreferences` with a Keystore-backed master key, so the file
 * on disk is not readable by anything that gets at the app's data directory
 * without also getting at the Keystore. Backup is disabled app-wide
 * (`data_extraction_rules.xml`), so a token cannot ride a cloud restore onto
 * a different phone.
 *
 * DataStore is used for settings instead; it is the better API but it has no
 * encryption layer, and these two values are the ones worth encrypting.
 */
class TokenStore(context: Context) {

    private val preferences: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    var accessToken: String?
        get() = preferences.getString(KEY_ACCESS, null)
        set(value) = preferences.edit().putString(KEY_ACCESS, value).apply()

    var refreshToken: String?
        get() = preferences.getString(KEY_REFRESH, null)
        set(value) = preferences.edit().putString(KEY_REFRESH, value).apply()

    var deviceId: String?
        get() = preferences.getString(KEY_DEVICE, null)
        set(value) = preferences.edit().putString(KEY_DEVICE, value).apply()

    val isEnrolled: Boolean get() = deviceId != null && refreshToken != null

    fun savePair(access: String, refresh: String) {
        preferences.edit()
            .putString(KEY_ACCESS, access)
            .putString(KEY_REFRESH, refresh)
            .apply()
    }

    /** Called on any 401 and on sign-out. Leaves nothing behind. */
    fun clearSession() {
        preferences.edit().remove(KEY_ACCESS).remove(KEY_REFRESH).apply()
    }

    fun clearEverything() {
        preferences.edit().clear().apply()
    }

    private companion object {
        const val FILE_NAME = "acs_tokens"
        const val KEY_ACCESS = "access_token"
        const val KEY_REFRESH = "refresh_token"
        const val KEY_DEVICE = "device_id"
    }
}
