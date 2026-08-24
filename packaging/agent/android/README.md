# BSDM Connect — Android Client Scaffolding

This directory contains the Android application for **BSDM Connect**, providing mobile users with:
1. **Adaptive Touch UI**: Embedded WebView connecting to the agent's PAC engine and control plane (`http://127.0.0.1:8765` or remote corporate gateway).
2. **Android VpnService**: Native Android VPN service (`BsdmVpnService`) establishing tunneled routes for corporate subnets.
3. **Android PAC Configuration**: Automated proxy configuration via Android Proxy Auto-Config.

## Building the Android APK

Requirements:
- Android SDK 34
- JDK 17
- Gradle 8.x

Commands:
```bash
cd packaging/agent/android
./gradlew assembleDebug
```
The output APK will be located at `app/build/outputs/apk/debug/app-debug.apk`.

## Quick Install on Android Device / Emulator

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
