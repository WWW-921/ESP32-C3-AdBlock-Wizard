#pragma once
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
static const char* WEB_USER = "admin";
static String wizardWebPass;
static String wizardOtaPass;
static String wizardApPass;
#define WEB_PASS (wizardWebPass.c_str())
#define OTA_PASS (wizardOtaPass.c_str())
