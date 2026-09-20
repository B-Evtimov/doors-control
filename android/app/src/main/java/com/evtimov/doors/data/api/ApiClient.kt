package com.evtimov.doors.data.api

import com.evtimov.doors.BuildConfig
import com.evtimov.doors.data.local.TokenStore
import java.net.HttpURLConnection
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import okhttp3.CertificatePinner
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/**
 * The HTTP stack.
 *
 * Three things here are security controls rather than plumbing:
 *
 *  - **Certificate pinning.** The pins are on the intermediate, not the leaf,
 *    so certificate renewal does not require an app release, and a backup pin
 *    is always shipped. Without backup pins, losing a key means every
 *    installed copy of the app stops working until users update.
 *  - **TLS 1.2 and above only**, via `ConnectionSpec.RESTRICTED_TLS`.
 *  - **One refresh at a time.** Token rotation with reuse detection means two
 *    concurrent refreshes would race, the second would present a token the
 *    first had already rotated, and the server would - correctly - revoke the
 *    whole family. The lock below is what keeps the app from triggering the
 *    server's own theft detection against itself.
 */
object ApiClient {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    fun create(tokenStore: TokenStore, onSessionLost: () -> Unit): AcsApi {
        val pinner = CertificatePinner.Builder().apply {
            BuildConfig.CERT_PINS.forEach { pin -> add(BuildConfig.API_HOST, pin) }
        }.build()

        val client = OkHttpClient.Builder()
            .certificatePinner(pinner)
            .connectionSpecs(listOf(okhttp3.ConnectionSpec.RESTRICTED_TLS))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .addInterceptor(AuthInterceptor(tokenStore))
            .addInterceptor(RefreshInterceptor(tokenStore, json, onSessionLost))
            .apply {
                if (BuildConfig.DEBUG) {
                    // Headers only. Never the bodies: they carry tokens.
                    addInterceptor(
                        okhttp3.logging.HttpLoggingInterceptor().apply {
                            level = okhttp3.logging.HttpLoggingInterceptor.Level.BASIC
                        }
                    )
                }
            }
            .build()

        return Retrofit.Builder()
            .baseUrl(BuildConfig.API_BASE_URL)
            .client(client)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
            .create(AcsApi::class.java)
    }

    private class AuthInterceptor(private val tokens: TokenStore) : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val token = tokens.accessToken
            if (token == null || request.url.encodedPath.contains("/auth/enroll")) {
                return chain.proceed(request)
            }
            return chain.proceed(
                request.newBuilder()
                    .header("Authorization", "Bearer $token")
                    .build()
            )
        }
    }

    private class RefreshInterceptor(
        private val tokens: TokenStore,
        private val json: Json,
        private val onSessionLost: () -> Unit,
    ) : Interceptor {

        override fun intercept(chain: Interceptor.Chain): Response {
            val response = chain.proceed(chain.request())
            if (response.code != HttpURLConnection.HTTP_UNAUTHORIZED) {
                return response
            }
            if (chain.request().url.encodedPath.contains("/auth/")) {
                // A 401 from the auth endpoints themselves is final.
                tokens.clearSession()
                onSessionLost()
                return response
            }

            response.close()

            val refreshed = synchronized(refreshLock) { refreshOnce(chain) }
            if (!refreshed) {
                tokens.clearSession()
                onSessionLost()
                return chain.proceed(chain.request())
            }

            return chain.proceed(
                chain.request().newBuilder()
                    .header("Authorization", "Bearer ${tokens.accessToken}")
                    .build()
            )
        }

        private fun refreshOnce(chain: Interceptor.Chain): Boolean {
            val refreshToken = tokens.refreshToken ?: return false

            val body = json.encodeToString(
                RefreshRequest.serializer(), RefreshRequest(refreshToken)
            ).toRequestBody()

            val request = Request.Builder()
                .url(chain.request().url.newBuilder()
                    .encodedPath("/api/v1/auth/refresh")
                    .query(null)
                    .build())
                .post(body)
                .build()

            return runCatching {
                chain.proceed(request).use { response ->
                    if (!response.isSuccessful) return@use false
                    val payload = response.body?.string() ?: return@use false
                    val pair = json.decodeFromString(TokenPair.serializer(), payload)
                    tokens.savePair(pair.accessToken, pair.refreshToken)
                    true
                }
            }.getOrDefault(false)
        }

        private fun String.toRequestBody() =
            okhttp3.RequestBody.create("application/json".toMediaType(), this)

        private companion object {
            /**
             * Refresh is serialised across the whole process. Two concurrent
             * refreshes would present the same rotated token twice and the
             * server would revoke the family - it cannot tell that race apart
             * from a stolen token, and it should not try.
             */
            val refreshLock = Any()
        }
    }
}
