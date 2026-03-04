# SentinelPass ProGuard Rules

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep JNI related classes
-keep class com.sentinelpass.VaultBridge { *; }
-keep class com.sentinelpass.** { *; }

# Keep data classes used with kotlinx.serialization
-keepattributes *Annotation*
-keepclassmembers,allowshrinking,allowobfuscation class * {
    @kotlinx.serialization.SerialName <fields>;
}

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.coroutines.** {
    volatile <fields>;
}

# Keep Compose runtime
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Preserve line numbers for debugging
-keepattributes SourceFile,LineNumberTable

# Remove logging
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
