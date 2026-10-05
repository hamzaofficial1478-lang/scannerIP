// AGP 9 compiles Kotlin itself, so there's no separate kotlin-android plugin.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Every GitHub build gets the next run number, so a phone can tell which build
// is newer. Local builds are 1.0-dev. The in-app updater fetches new builds
// from this repository's "latest" release.
val runNumber = providers.environmentVariable("GITHUB_RUN_NUMBER").orNull?.toIntOrNull()
val updateRepo = providers.environmentVariable("GITHUB_REPOSITORY").orNull ?: "hamzaofficial1478-lang/scannerIP"

android {
    namespace = "io.github.scannerip.app"
    // tor-android 0.4.9.13 is built against Android 17 (API 37.1).
    compileSdk {
        version = release(37) { minorApiLevel = 1 }
    }

    defaultConfig {
        applicationId = "io.github.scannerip.app"
        minSdk = 26
        // Kept at 36 on purpose: Android 17 behaviour changes haven't been tested on a real phone yet.
        targetSdk = 36
        versionCode = runNumber ?: 1
        versionName = if (runNumber != null) "1.0.$runNumber" else "1.0-dev"
        buildConfigField("String", "UPDATE_URL", "\"https://github.com/$updateRepo/releases/download/latest/\"")
        // Real phones (64 and 32-bit ARM) plus x86_64 for the Android emulator.
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    signingConfigs {
        // A demo key kept in the repo so every build installs over the last one.
        // Fine for a school project you sideload. Make your own key before
        // publishing anywhere, because anyone can sign with this one.
        create("demo") {
            storeFile = file("scannerip-demo.jks")
            storePassword = "scannerip"
            keyAlias = "scannerip"
            keyPassword = "scannerip"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("demo")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all { test ->
            // Optional: -ProbolectricRepo=<maven mirror> if Maven Central rate-limits you.
            providers.gradleProperty("robolectricRepo").orNull?.let {
                test.systemProperty("robolectric.dependency.repo.url", it)
            }
            test.maxHeapSize = "2g"
        }
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    lint {
        disable += "OldTargetApi" // see targetSdk above
        warningsAsErrors = true
        abortOnError = true
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.cpp)
    implementation(libs.tor.android)
    implementation(libs.work.runtime)
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit4)
    testImplementation(libs.robolectric)
    testImplementation(platform(libs.compose.bom))
    testImplementation(libs.compose.ui.test.junit4)
    testImplementation(libs.work.testing)
    testImplementation(libs.okhttp.mockwebserver)
}
