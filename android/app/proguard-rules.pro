# Retrofit interfaces are reflected over.
-keepattributes Signature, InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}

# kotlinx.serialization keeps its generated serializers reachable.
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class com.evtimov.doors.data.api.** {
    kotlinx.serialization.KSerializer serializer(...);
}

-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
