# Tor's native code reads and writes fields and calls methods on TorService
# by name through JNI, so R8 must not rename or strip anything there.
-keep class org.torproject.jni.** { *; }
-keep class net.freehaven.tor.control.** { *; }

# zxing-cpp ships its own keep rules; this is belt and braces for JNI.
-keep class zxingcpp.** { *; }

# The scan log is (de)serialised with kotlinx.serialization.
-keepclassmembers class io.github.scannerip.core.ScanEntry { *; }
-keep class io.github.scannerip.core.ScanEntry$$serializer { *; }

# OkHttp's optional TLS providers aren't on Android.
-dontwarn org.bouncycastle.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
