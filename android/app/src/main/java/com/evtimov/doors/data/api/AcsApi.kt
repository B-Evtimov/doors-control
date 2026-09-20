package com.evtimov.doors.data.api

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface AcsApi {

    @POST("api/v1/auth/enroll/challenge")
    suspend fun enrollChallenge(@Body body: EnrollChallengeRequest): EnrollChallengeResponse

    @POST("api/v1/auth/enroll")
    suspend fun enroll(@Body body: EnrollRequest): EnrollResponse

    @POST("api/v1/auth/login")
    suspend fun login(@Body body: LoginRequest): TokenPair

    @POST("api/v1/auth/refresh")
    suspend fun refresh(@Body body: RefreshRequest): Response<TokenPair>

    @POST("api/v1/auth/logout")
    suspend fun logout(@Body body: LogoutRequest): Response<Unit>

    @GET("api/v1/doors")
    suspend fun doors(): DoorListResponse

    @POST("api/v1/doors/{doorId}/unlock")
    suspend fun unlock(
        @Path("doorId") doorId: String,
        @Body body: UnlockRequest,
    ): UnlockResponse

    @GET("api/v1/me/access-history")
    suspend fun accessHistory(@Query("limit") limit: Int = 50): AccessHistoryResponse
}
