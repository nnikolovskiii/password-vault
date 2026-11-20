plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.nnikolovskii.vault"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.nnikolovskii.vault"
        // 28: StrongBox, setUnlockedDeviceRequired, clearPrimaryClip.
        minSdk = 28
        targetSdk = 36
        versionCode = 3
        versionName = "0.3.0"
    }

    buildTypes {
        release {
            // R8 strips the unused parts of Bouncy Castle.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            // A debug build must never collide with the release vault: a signature mismatch
            // there would tempt an uninstall, and uninstalling deletes the vault.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // BuildConfig.DEBUG gates the KDF timing line on Unlock.
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = false
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests.all {
            // Argon2id at the real 64 MiB floor runs in the tests.
            it.maxHeapSize = "512m"
        }
    }
}

ksp {
    // Exported Room schema JSON lives in app/schemas/ and is committed. v1 froze at 0.1.0;
    // v2 (0.2.0) adds vault_meta.backupInfo, v3 (0.3.0) the biometric / passphrase / settings
    // columns, each through a real migration.
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    val bom = platform("androidx.compose:compose-bom:2025.12.01")
    implementation(bom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    val room = "2.7.1"
    implementation("androidx.room:room-runtime:$room")
    implementation("androidx.room:room-ktx:$room")
    ksp("androidx.room:room-compiler:$room")

    // Argon2id only, through the lightweight API (not the JCA provider).
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    // Test-only: runs the Room migration SQL against the exported schema JSON on the JVM.
    testImplementation("org.xerial:sqlite-jdbc:3.41.2.2")
}
