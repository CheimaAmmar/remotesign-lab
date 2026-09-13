#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

#include <ArduinoJson.h>

#include "secrets.h"
#include "trust_anchor.h"

#ifndef REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  #ifdef __has_include
    #if __has_include(<SPI.h>) \
      && __has_include(<MFRC522.h>) \
      && __has_include(<Adafruit_Fingerprint.h>)
      #define REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE 1
    #else
      #define REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE 0
    #endif
  #else
    #define REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE 0
  #endif
#endif

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  #include <SPI.h>
  #include <MFRC522.h>
  #include <Adafruit_Fingerprint.h>
#endif

#include <mbedtls/md.h>

#include <time.h>
#include <esp_system.h>
#include <stdio.h>


// ======================================================
// WIFI
// ======================================================




// ======================================================
// DEVICE
// ======================================================

const char* DEVICE_UID =
  "ESP32-001";

// HMAC secret: 64 hexadecimal characters


// ======================================================
// HTTPS SERVER
// ======================================================

const char* SERVER_BASE =
  "https://172.20.10.4:8443";

const char* NEXT_REQUEST_PATH =
  "/api/v1/device/signature-requests/next";

const char* CHALLENGE_PATH =
  "/api/v1/auth/challenge";

const char* COMPLETE_PATH =
  "/api/v1/auth/complete";
  
const char* SIGN_PATH =
  "/api/v1/sign";

// ======================================================
// QUEUE AND TIMING
// ======================================================

constexpr unsigned long POLL_INTERVAL_MS = 3000;
constexpr unsigned long RETRY_INTERVAL_MS = 3000;
constexpr unsigned long RFID_TIMEOUT_MS = 60000;
constexpr unsigned long FINGERPRINT_TIMEOUT_MS = 60000;

// ======================================================
// AUTHENTICATION MODE
// ======================================================

constexpr bool SIMULATE_AUTH_FACTORS = true;

const String SIMULATED_RFID_UID =
  "69:89:6E:14";

constexpr int SIMULATED_FINGERPRINT_ID = 1;

static_assert(
  SIMULATE_AUTH_FACTORS
  || REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE,
  "Install MFRC522 and Adafruit Fingerprint for real hardware mode"
);

// ======================================================
// RC522 - WIRING TO COMPLETE BEFORE USE
// ======================================================

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE

// -1 is an intentional sentinel: it is not a GPIO selection.
// The firmware refuses to start the workflow until these five values
// have been replaced with the actual wiring.
constexpr int RC522_SCK_PIN = -1;
constexpr int RC522_MOSI_PIN = -1;
constexpr int RC522_MISO_PIN = -1;
constexpr int RC522_SS_PIN = -1;
constexpr int RC522_RST_PIN = -1;

// ======================================================
// DY50 - UART FROM THE PREVIOUS PROTOTYPE
// ======================================================

constexpr int FP_RX_PIN = 1;
constexpr int FP_TX_PIN = 0;
constexpr uint32_t FINGERPRINT_BAUD = 57600;

MFRC522 rfidReader;
HardwareSerial fingerprintSerial(1);
Adafruit_Fingerprint finger(&fingerprintSerial);

#endif


// ======================================================
// WORKFLOW TYPES AND STATE
// ======================================================

struct SignatureRequest {
  String requestId;
  String documentId;
  String documentHash;
  String decision;

  void clear() {
    requestId = "";
    documentId = "";
    documentHash = "";
    decision = "";
  }
};

enum class FetchResult {
  REQUEST_AVAILABLE,
  NO_REQUEST,
  RETRY_LATER
};

enum class StepResult {
  SUCCESS,
  TEMPORARY_ERROR,
  DEFINITIVE_ERROR
};

enum class WorkflowState {
  IDLE,
  POLL_NEXT,
  WAIT_RFID,
  CHALLENGE,
  WAIT_FINGERPRINT,
  COMPLETE_AUTH,
  SIGN_DOCUMENT,
  REPORT_FAILED,
  SUCCESS
};

constexpr int FINGERPRINT_WAITING = -1;
constexpr int FINGERPRINT_RETRY_SAMPLE = -2;
constexpr int FINGERPRINT_SENSOR_ERROR = -3;
constexpr unsigned long FINGERPRINT_POLL_INTERVAL_MS = 150;

SignatureRequest currentRequest;
WorkflowState workflowState = WorkflowState::IDLE;

String currentRfidUid;
String currentSessionId;
String currentChallenge;
String pendingFailureCode;
String completedSignatureId;
String completedAlgorithm;

int currentFingerprintId = -1;

bool rfidReady = false;
bool fingerprintReady = false;
bool hardwareReady = false;

unsigned long stateStartedAt = 0;
unsigned long lastPollAt = 0;
unsigned long nextActionAt = 0;
unsigned long lastFingerprintPollAt = 0;


// ======================================================
// VALIDATION AND NORMALIZATION
// ======================================================

bool isHexCharacter(char value) {
  return (
    (value >= '0' && value <= '9')
    || (value >= 'a' && value <= 'f')
    || (value >= 'A' && value <= 'F')
  );
}

bool isHexString(const String& value, size_t expectedLength) {
  if (value.length() != expectedLength) {
    return false;
  }

  for (size_t i = 0; i < value.length(); ++i) {
    if (!isHexCharacter(value.charAt(i))) {
      return false;
    }
  }

  return true;
}

bool isUuidString(const String& value) {
  if (value.length() != 36) {
    return false;
  }

  for (size_t i = 0; i < value.length(); ++i) {
    const bool separator = (
      i == 8 || i == 13 || i == 18 || i == 23
    );

    if (separator) {
      if (value.charAt(i) != '-') {
        return false;
      }
    } else if (!isHexCharacter(value.charAt(i))) {
      return false;
    }
  }

  return true;
}

String normalizedDeviceUid() {
  String uid(DEVICE_UID);
  uid.trim();
  uid.toUpperCase();
  return uid;
}

bool validateSignatureRequest(SignatureRequest& request) {
  request.requestId.trim();
  request.documentId.trim();
  request.documentHash.trim();
  request.decision.trim();

  request.requestId.toLowerCase();
  request.documentId.toLowerCase();
  request.documentHash.toLowerCase();
  request.decision.toUpperCase();

  return (
    isUuidString(request.requestId)
    && isUuidString(request.documentId)
    && isHexString(request.documentHash, 64)
    && request.decision == "APPROVE"
  );
}

bool normalizeFailureCode(
  const String& rawFailureCode,
  String& failureCode
) {
  failureCode = rawFailureCode;
  failureCode.trim();
  failureCode.toUpperCase();

  if (
    failureCode.length() < 3
    || failureCode.length() > 64
  ) {
    return false;
  }

  for (size_t i = 0; i < failureCode.length(); ++i) {
    const char value = failureCode.charAt(i);

    if (
      !(
        (value >= 'A' && value <= 'Z')
        || (value >= '0' && value <= '9')
        || value == '_'
      )
    ) {
      return false;
    }
  }

  return true;
}

bool isTemporaryHttpStatus(int httpCode) {
  return (
    httpCode < 0
    || httpCode == 408
    || httpCode == 425
    || httpCode == 429
    || httpCode >= 500
  );
}

bool intervalElapsed(
  unsigned long startedAt,
  unsigned long duration
) {
  return (
    static_cast<unsigned long>(millis() - startedAt)
    >= duration
  );
}

bool actionDue() {
  return (
    static_cast<long>(millis() - nextActionAt)
    >= 0
  );
}


// ======================================================
// HEX SECRET -> BYTES
// ======================================================

int hexNibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }

  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }

  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }

  return -1;
}

bool hexToBytes(
  const char* hex,
  uint8_t* output,
  size_t outputLength
) {
  if (
    hex == nullptr
    || strlen(hex) != outputLength * 2
  ) {
    return false;
  }

  for (size_t i = 0; i < outputLength; ++i) {
    const int high = hexNibble(hex[i * 2]);
    const int low = hexNibble(hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      return false;
    }

    output[i] = static_cast<uint8_t>(
      (high << 4) | low
    );
  }

  return true;
}


// ======================================================
// RANDOM 128-BIT NONCE
// ======================================================

String generateNonce() {
  char nonce[33];

  for (int i = 0; i < 16; ++i) {
    const uint8_t value = esp_random() & 0xFF;
    snprintf(
      &nonce[i * 2],
      3,
      "%02x",
      value
    );
  }

  nonce[32] = '\0';
  return String(nonce);
}


// ======================================================
// HMAC-SHA256
// ======================================================

String calculateHMAC(const String& message) {
  uint8_t secretBytes[32];

  if (
    !hexToBytes(
      DEVICE_SECRET,
      secretBytes,
      sizeof(secretBytes)
    )
  ) {
    Serial.println("ERROR: invalid DEVICE_SECRET");
    return "";
  }

  const mbedtls_md_info_t* info =
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (info == nullptr) {
    memset(secretBytes, 0, sizeof(secretBytes));
    Serial.println("ERROR: SHA-256 unavailable");
    return "";
  }

  unsigned char result[32];

  const int status = mbedtls_md_hmac(
    info,
    secretBytes,
    sizeof(secretBytes),
    reinterpret_cast<const unsigned char*>(
      message.c_str()
    ),
    message.length(),
    result
  );

  memset(secretBytes, 0, sizeof(secretBytes));

  if (status != 0) {
    Serial.println("ERROR: unable to calculate HMAC");
    return "";
  }

  char hexResult[65];

  for (int i = 0; i < 32; ++i) {
    snprintf(
      &hexResult[i * 2],
      3,
      "%02x",
      result[i]
    );
  }

  hexResult[64] = '\0';
  return String(hexResult);
}


// ======================================================
// WI-FI AND NTP
// ======================================================

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.println();
  Serial.println("Connecting to Wi-Fi...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  const unsigned long startedAt = millis();

  while (
    WiFi.status() != WL_CONNECTED
    && !intervalElapsed(startedAt, 20000)
  ) {
    delay(250);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi unavailable");
    return false;
  }

  Serial.println("Wi-Fi connected");
  return true;
}

bool syncTime() {
  if (time(nullptr) >= 1700000000) {
    return true;
  }

  Serial.println("Synchronizing NTP...");

  configTime(
    0,
    0,
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com"
  );

  const unsigned long startedAt = millis();

  while (
    time(nullptr) < 1700000000
    && !intervalElapsed(startedAt, 20000)
  ) {
    delay(250);
  }

  if (time(nullptr) < 1700000000) {
    Serial.println("NTP unavailable");
    return false;
  }

  Serial.println("NTP synchronized");
  return true;
}

bool ensureNetworkReady() {
  return connectWiFi() && syncTime();
}

bool testServerConnection() {
  if (!ensureNetworkReady()) {
    return false;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url = String(SERVER_BASE) + "/docs";

  if (!http.begin(secureClient, url)) {
    http.end();
    Serial.println("Unable to initialize HTTPS");
    return false;
  }

  http.setTimeout(10000);
  const int httpCode = http.GET();
  http.end();

  if (httpCode == 200) {
    Serial.println("HTTPS server reachable");
    return true;
  }

  Serial.print("HTTPS server temporarily unavailable: ");
  Serial.println(httpCode);
  return false;
}


// ======================================================
// RC522 INITIALIZATION
// ======================================================

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE

bool rc522PinsConfigured() {
  return (
    RC522_SCK_PIN >= 0
    && RC522_MOSI_PIN >= 0
    && RC522_MISO_PIN >= 0
    && RC522_SS_PIN >= 0
    && RC522_RST_PIN >= 0
  );
}

#endif

bool initializeRFID() {
  if (SIMULATE_AUTH_FACTORS) {
    Serial.println("RFID in simulation mode");
    return true;
  }

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  if (!rc522PinsConfigured()) {
    Serial.println();
    Serial.println("RC522 not configured.");
    Serial.println("Set SCK, MOSI, MISO, SS/SDA, and RST.");
    return false;
  }

  SPI.begin(
    RC522_SCK_PIN,
    RC522_MISO_PIN,
    RC522_MOSI_PIN,
    RC522_SS_PIN
  );

  rfidReader.PCD_Init(
    static_cast<byte>(RC522_SS_PIN),
    static_cast<byte>(RC522_RST_PIN)
  );

  delay(4);

  const byte version =
    rfidReader.PCD_ReadRegister(MFRC522::VersionReg);

  if (version == 0x00 || version == 0xFF) {
    Serial.println("RC522 not detected");
    return false;
  }

  Serial.println("RC522 initialized");
  return true;
#else
  Serial.println("MFRC522 library unavailable");
  return false;
#endif
}

bool readRFID(String& uid) {
  if (SIMULATE_AUTH_FACTORS) {
    uid = SIMULATED_RFID_UID;
    Serial.println("SIMULATED RFID");
    Serial.print("UID: ");
    Serial.println(uid);
    return true;
  }

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  uid = "";

  if (!rfidReady) {
    return false;
  }

  if (!rfidReader.PICC_IsNewCardPresent()) {
    return false;
  }

  if (!rfidReader.PICC_ReadCardSerial()) {
    return false;
  }

  uid.reserve(rfidReader.uid.size * 3);

  for (byte i = 0; i < rfidReader.uid.size; ++i) {
    if (i > 0) {
      uid += ':';
    }

    char byteAsHex[3];
    snprintf(
      byteAsHex,
      sizeof(byteAsHex),
      "%02X",
      rfidReader.uid.uidByte[i]
    );
    uid += byteAsHex;
  }

  rfidReader.PICC_HaltA();
  rfidReader.PCD_StopCrypto1();

  return uid.length() > 0;
#else
  uid = "";
  return false;
#endif
}


// ======================================================
// DY50 INITIALIZATION AND RECOGNITION
// ======================================================

bool initializeFingerprint() {
  if (SIMULATE_AUTH_FACTORS) {
    Serial.println("DY50 in simulation mode");
    return true;
  }

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  fingerprintSerial.begin(
    FINGERPRINT_BAUD,
    SERIAL_8N1,
    FP_RX_PIN,
    FP_TX_PIN
  );

  delay(1000);

  if (!finger.verifyPassword()) {
    Serial.println("DY50 not detected or password invalid");
    return false;
  }

  Serial.println("DY50 initialized");

  if (finger.getTemplateCount() == FINGERPRINT_OK) {
    Serial.print("Stored fingerprints: ");
    Serial.println(finger.templateCount);
  }

  return true;
#else
  Serial.println("Adafruit Fingerprint library unavailable");
  return false;
#endif
}

int recognizeFingerprint() {
  if (SIMULATE_AUTH_FACTORS) {
    Serial.println("SIMULATED DY50");
    Serial.print("Fingerprint ID: ");
    Serial.println(SIMULATED_FINGERPRINT_ID);
    return SIMULATED_FINGERPRINT_ID;
  }

#if REMOTESIGN_LAB_AUTH_HARDWARE_AVAILABLE
  if (!fingerprintReady) {
    return FINGERPRINT_SENSOR_ERROR;
  }

  uint8_t result = finger.getImage();

  if (result == FINGERPRINT_NOFINGER) {
    return FINGERPRINT_WAITING;
  }

  if (result != FINGERPRINT_OK) {
    return FINGERPRINT_SENSOR_ERROR;
  }

  result = finger.image2Tz();

  if (result != FINGERPRINT_OK) {
    Serial.println("Unreadable fingerprint, try again");
    return FINGERPRINT_RETRY_SAMPLE;
  }

  result = finger.fingerSearch();

  if (result == FINGERPRINT_OK) {
    return static_cast<int>(finger.fingerID);
  }

  if (result == FINGERPRINT_NOTFOUND) {
    Serial.println("Fingerprint not recognized");
    return FINGERPRINT_RETRY_SAMPLE;
  }

  return FINGERPRINT_SENSOR_ERROR;
#else
  return FINGERPRINT_SENSOR_ERROR;
#endif
}


// ======================================================
// POLLING /next
// ======================================================

FetchResult fetchNextSignatureRequest(
  SignatureRequest& request
) {
  request.clear();

  if (!ensureNetworkReady()) {
    return FetchResult::RETRY_LATER;
  }

  const String timestamp = String(
    static_cast<uint32_t>(time(nullptr))
  );
  const String nonce = generateNonce();
  const String deviceUid = normalizedDeviceUid();

  // POST\n/path\ntimestamp\nnonce\nDEVICE_UID
  const String canonical =
    String("POST")
    + "\n" + NEXT_REQUEST_PATH
    + "\n" + timestamp
    + "\n" + nonce
    + "\n" + deviceUid;

  const String signature = calculateHMAC(canonical);

  if (signature.length() == 0) {
    return FetchResult::RETRY_LATER;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url =
    String(SERVER_BASE) + NEXT_REQUEST_PATH;

  if (!http.begin(secureClient, url)) {
    http.end();
    return FetchResult::RETRY_LATER;
  }

  http.setTimeout(10000);
  http.addHeader("X-Device-UID", deviceUid);
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Signature", signature);

  const int httpCode = http.POST("");

  if (httpCode == 204) {
    http.end();
    Serial.println("No request");
    return FetchResult::NO_REQUEST;
  }

  if (httpCode < 0) {
    Serial.print("Network error on /next: ");
    Serial.println(HTTPClient::errorToString(httpCode));
    http.end();
    return FetchResult::RETRY_LATER;
  }

  if (httpCode != 200) {
    Serial.print("HTTP /next: ");
    Serial.println(httpCode);

    if (httpCode == 401 || httpCode == 403) {
      Serial.println("Device authentication denied");
    }

    http.end();
    return FetchResult::RETRY_LATER;
  }

  const String response = http.getString();
  http.end();

  JsonDocument document;

  const DeserializationError error =
    deserializeJson(document, response);

  if (error) {
    Serial.println("Invalid JSON response from /next");
    return FetchResult::RETRY_LATER;
  }

  request.requestId =
    document["request_id"].as<String>();
  request.documentId =
    document["document_id"].as<String>();
  request.documentHash =
    document["document_hash"].as<String>();
  request.decision =
    document["decision"].as<String>();

  if (!validateSignatureRequest(request)) {
    Serial.println("Invalid data from /next");
    request.clear();
    return FetchResult::RETRY_LATER;
  }

  return FetchResult::REQUEST_AVAILABLE;
}


// ======================================================
// /auth/challenge
// ======================================================

StepResult requestChallenge(
  const SignatureRequest& request,
  const String& rfidUid,
  String& sessionId,
  String& challenge
) {
  if (!ensureNetworkReady()) {
    return StepResult::TEMPORARY_ERROR;
  }

  const String timestamp = String(
    static_cast<uint32_t>(time(nullptr))
  );
  const String nonce = generateNonce();

  // No request_id or device UID in this canonical payload.
  const String canonical =
    String("POST")
    + "\n" + CHALLENGE_PATH
    + "\n" + timestamp
    + "\n" + nonce
    + "\n" + rfidUid
    + "\n" + request.documentId
    + "\n" + request.documentHash
    + "\n" + request.decision;

  const String signature = calculateHMAC(canonical);

  if (signature.length() == 0) {
    return StepResult::DEFINITIVE_ERROR;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url =
    String(SERVER_BASE) + CHALLENGE_PATH;

  if (!http.begin(secureClient, url)) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  http.setTimeout(10000);
  http.addHeader("X-Device-UID", normalizedDeviceUid());
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-RFID-UID", rfidUid);
  http.addHeader("X-Document-ID", request.documentId);
  http.addHeader("X-Document-Hash", request.documentHash);
  http.addHeader("X-Decision", request.decision);
  http.addHeader("X-Signature", signature);

  const int httpCode = http.POST("");

  Serial.print("HTTP challenge: ");
  Serial.println(httpCode);

  if (httpCode < 0) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  if (httpCode != 200) {
    http.end();

    return (
      isTemporaryHttpStatus(httpCode)
      ? StepResult::TEMPORARY_ERROR
      : StepResult::DEFINITIVE_ERROR
    );
  }

  const String response = http.getString();
  http.end();

  JsonDocument document;

  if (deserializeJson(document, response)) {
    return StepResult::DEFINITIVE_ERROR;
  }

  sessionId = document["session_id"].as<String>();
  challenge = document["challenge"].as<String>();

  sessionId.trim();
  sessionId.toLowerCase();
  challenge.trim();
  challenge.toLowerCase();

  const String returnedDocumentId =
    document["document_id"].as<String>();
  const String returnedHash =
    document["document_hash"].as<String>();
  const String returnedDecision =
    document["decision"].as<String>();

  if (
    !isUuidString(sessionId)
    || !isHexString(challenge, 64)
    || (
      returnedDocumentId.length() > 0
      && returnedDocumentId != request.documentId
    )
    || (
      returnedHash.length() > 0
      && returnedHash != request.documentHash
    )
    || (
      returnedDecision.length() > 0
      && returnedDecision != request.decision
    )
  ) {
    return StepResult::DEFINITIVE_ERROR;
  }

  return StepResult::SUCCESS;
}


// ======================================================
// /auth/complete
// ======================================================

StepResult completeAuthentication(
  const SignatureRequest& request,
  const String& rfidUid,
  int fingerprintId,
  const String& sessionId,
  const String& challenge
) {
  if (!ensureNetworkReady()) {
    return StepResult::TEMPORARY_ERROR;
  }

  const String timestamp = String(
    static_cast<uint32_t>(time(nullptr))
  );
  const String nonce = generateNonce();
  const String fingerprintString =
    String(fingerprintId);

  // No request_id or device UID in this canonical payload.
  const String canonical =
    String("POST")
    + "\n" + COMPLETE_PATH
    + "\n" + timestamp
    + "\n" + nonce
    + "\n" + sessionId
    + "\n" + challenge
    + "\n" + rfidUid
    + "\n" + fingerprintString
    + "\n" + request.documentId
    + "\n" + request.documentHash
    + "\n" + request.decision;

  const String signature = calculateHMAC(canonical);

  if (signature.length() == 0) {
    return StepResult::DEFINITIVE_ERROR;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url =
    String(SERVER_BASE) + COMPLETE_PATH;

  if (!http.begin(secureClient, url)) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  http.setTimeout(10000);
  http.addHeader("X-Device-UID", normalizedDeviceUid());
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Session-ID", sessionId);
  http.addHeader("X-Challenge", challenge);
  http.addHeader("X-RFID-UID", rfidUid);
  http.addHeader("X-Fingerprint-ID", fingerprintString);
  http.addHeader("X-Document-ID", request.documentId);
  http.addHeader("X-Document-Hash", request.documentHash);
  http.addHeader("X-Decision", request.decision);
  http.addHeader("X-Signature", signature);

  const int httpCode = http.POST("");

  Serial.print("HTTP complete: ");
  Serial.println(httpCode);

  if (httpCode < 0) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  if (httpCode != 200) {
    http.end();

    return (
      isTemporaryHttpStatus(httpCode)
      ? StepResult::TEMPORARY_ERROR
      : StepResult::DEFINITIVE_ERROR
    );
  }

  const String response = http.getString();
  http.end();

  JsonDocument document;

  if (deserializeJson(document, response)) {
    return StepResult::DEFINITIVE_ERROR;
  }

  const bool authenticated =
    document["authenticated"] | false;

  return (
    authenticated
    ? StepResult::SUCCESS
    : StepResult::DEFINITIVE_ERROR
  );
}


// ======================================================
// /sign
// ======================================================

StepResult signDocument(
  const SignatureRequest& request,
  const String& sessionId,
  String& signatureId,
  String& algorithm
) {
  if (!ensureNetworkReady()) {
    return StepResult::TEMPORARY_ERROR;
  }

  const String timestamp = String(
    static_cast<uint32_t>(time(nullptr))
  );
  const String nonce = generateNonce();

  // No request_id or device UID in this canonical payload.
  const String canonical =
    String("POST")
    + "\n" + SIGN_PATH
    + "\n" + timestamp
    + "\n" + nonce
    + "\n" + sessionId
    + "\n" + request.documentId
    + "\n" + request.documentHash
    + "\n" + request.decision;

  const String signature = calculateHMAC(canonical);

  if (signature.length() == 0) {
    return StepResult::DEFINITIVE_ERROR;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url = String(SERVER_BASE) + SIGN_PATH;

  if (!http.begin(secureClient, url)) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  http.setTimeout(15000);
  http.addHeader("X-Device-UID", normalizedDeviceUid());
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Session-ID", sessionId);
  http.addHeader("X-Document-ID", request.documentId);
  http.addHeader("X-Document-Hash", request.documentHash);
  http.addHeader("X-Decision", request.decision);
  http.addHeader("X-Signature", signature);

  const int httpCode = http.POST("");

  Serial.print("HTTP sign: ");
  Serial.println(httpCode);

  if (httpCode < 0) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  if (httpCode != 200) {
    http.end();

    return (
      isTemporaryHttpStatus(httpCode)
      ? StepResult::TEMPORARY_ERROR
      : StepResult::DEFINITIVE_ERROR
    );
  }

  // Keep only the three useful fields in RAM. The potentially large
  // signature_base64 field is ignored while parsing the HTTP stream.
  JsonDocument filter;
  filter["signed"] = true;
  filter["signature_id"] = true;
  filter["algorithm"] = true;

  JsonDocument document;

  const DeserializationError jsonError = deserializeJson(
    document,
    http.getStream(),
    DeserializationOption::Filter(filter)
  );

  http.end();

  if (jsonError) {
    return StepResult::DEFINITIVE_ERROR;
  }

  const bool signedDocument =
    document["signed"] | false;

  signatureId =
    document["signature_id"].as<String>();
  algorithm =
    document["algorithm"].as<String>();

  return (
    signedDocument
    ? StepResult::SUCCESS
    : StepResult::DEFINITIVE_ERROR
  );
}


// ======================================================
// /signature-requests/{request_id}/status
// ======================================================

StepResult reportRequestFailure(
  const String& requestId,
  const String& rawFailureCode
) {
  String failureCode;

  if (
    requestId.length() == 0
    || !normalizeFailureCode(
      rawFailureCode,
      failureCode
    )
  ) {
    return StepResult::DEFINITIVE_ERROR;
  }

  if (!ensureNetworkReady()) {
    return StepResult::TEMPORARY_ERROR;
  }

  const String timestamp = String(
    static_cast<uint32_t>(time(nullptr))
  );
  const String nonce = generateNonce();
  const String deviceUid = normalizedDeviceUid();
  const String path =
    String("/api/v1/device/signature-requests/")
    + requestId
    + "/status";

  // The /status segment is part of the canonical payload.
  const String canonical =
    String("POST")
    + "\n" + path
    + "\n" + timestamp
    + "\n" + nonce
    + "\n" + deviceUid
    + "\nFAILED"
    + "\n" + failureCode;

  const String signature = calculateHMAC(canonical);

  if (signature.length() == 0) {
    return StepResult::DEFINITIVE_ERROR;
  }

  JsonDocument payload;
  payload["state"] = "FAILED";
  payload["failure_code"] = failureCode;

  String body;
  serializeJson(payload, body);

  WiFiClientSecure secureClient;
  secureClient.setCACert(SERVER_CA_CERT);

  HTTPClient http;
  const String url = String(SERVER_BASE) + path;

  if (!http.begin(secureClient, url)) {
    http.end();
    return StepResult::TEMPORARY_ERROR;
  }

  http.setTimeout(10000);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-UID", deviceUid);
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Signature", signature);

  const int httpCode = http.POST(body);

  Serial.print("HTTP status FAILED: ");
  Serial.println(httpCode);

  http.end();

  if (httpCode == 200) {
    return StepResult::SUCCESS;
  }

  return (
    isTemporaryHttpStatus(httpCode)
    ? StepResult::TEMPORARY_ERROR
    : StepResult::DEFINITIVE_ERROR
  );
}


// ======================================================
// STATE MACHINE
// ======================================================

void enterState(WorkflowState newState) {
  workflowState = newState;
  stateStartedAt = millis();
  nextActionAt = millis();
}

void clearWorkflow() {
  currentRequest.clear();
  currentRfidUid = "";
  currentSessionId = "";
  currentChallenge = "";
  pendingFailureCode = "";
  completedSignatureId = "";
  completedAlgorithm = "";
  currentFingerprintId = -1;

  lastPollAt = millis();
  enterState(WorkflowState::IDLE);
}

void beginDefinitiveFailure(const String& failureCode) {
  pendingFailureCode = failureCode;
  Serial.println();
  Serial.println("Definitive workflow failure");
  enterState(WorkflowState::REPORT_FAILED);
}

void printNewRequest() {
  Serial.println();
  Serial.println("================================");
  Serial.println(" NEW REQUEST");
  Serial.println("================================");
  Serial.print("Request ID: ");
  Serial.println(currentRequest.requestId);
  Serial.print("Document ID: ");
  Serial.println(currentRequest.documentId);
  Serial.print("SHA-256: ");
  Serial.println(currentRequest.documentHash);
  Serial.print("Decision: ");
  Serial.println(currentRequest.decision);
  Serial.println();

  if (SIMULATE_AUTH_FACTORS) {
    Serial.println("================================");
    Serial.println(" SIMULATED AUTHENTICATION");
    Serial.println("================================");
  } else {
    Serial.println("Present your RFID card...");
  }
}

void processWorkflow() {
  switch (workflowState) {
    case WorkflowState::IDLE:
      if (intervalElapsed(lastPollAt, POLL_INTERVAL_MS)) {
        enterState(WorkflowState::POLL_NEXT);
      }
      break;

    case WorkflowState::POLL_NEXT: {
      const FetchResult result =
        fetchNextSignatureRequest(currentRequest);

      lastPollAt = millis();

      if (result == FetchResult::REQUEST_AVAILABLE) {
        printNewRequest();
        enterState(WorkflowState::WAIT_RFID);
      } else {
        enterState(WorkflowState::IDLE);
      }
      break;
    }

    case WorkflowState::WAIT_RFID:
      if (intervalElapsed(stateStartedAt, RFID_TIMEOUT_MS)) {
        beginDefinitiveFailure("RFID_TIMEOUT");
        break;
      }

      if (readRFID(currentRfidUid)) {
        if (!SIMULATE_AUTH_FACTORS) {
          Serial.print("RFID read: ");
          Serial.println(currentRfidUid);
        }
        enterState(WorkflowState::CHALLENGE);
      }
      break;

    case WorkflowState::CHALLENGE: {
      if (!actionDue()) {
        break;
      }

      const StepResult result = requestChallenge(
        currentRequest,
        currentRfidUid,
        currentSessionId,
        currentChallenge
      );

      if (result == StepResult::SUCCESS) {
        Serial.println("RFID accepted");

        if (!SIMULATE_AUTH_FACTORS) {
          Serial.println();
          Serial.println("Place your finger...");
        }

        lastFingerprintPollAt = 0;
        enterState(WorkflowState::WAIT_FINGERPRINT);
      } else if (
        result == StepResult::TEMPORARY_ERROR
      ) {
        Serial.println("Challenge temporarily unavailable, retrying");
        nextActionAt = millis() + RETRY_INTERVAL_MS;
      } else {
        beginDefinitiveFailure("CHALLENGE_REJECTED");
      }
      break;
    }

    case WorkflowState::WAIT_FINGERPRINT:
      if (
        intervalElapsed(
          stateStartedAt,
          FINGERPRINT_TIMEOUT_MS
        )
      ) {
        beginDefinitiveFailure("FINGERPRINT_TIMEOUT");
        break;
      }

      if (
        !intervalElapsed(
          lastFingerprintPollAt,
          FINGERPRINT_POLL_INTERVAL_MS
        )
      ) {
        break;
      }

      lastFingerprintPollAt = millis();
      currentFingerprintId = recognizeFingerprint();

      if (currentFingerprintId > 0) {
        if (!SIMULATE_AUTH_FACTORS) {
          Serial.println("Fingerprint recognized");
          Serial.print("Fingerprint ID: ");
          Serial.println(currentFingerprintId);
        }
        enterState(WorkflowState::COMPLETE_AUTH);
      } else if (
        currentFingerprintId
        == FINGERPRINT_SENSOR_ERROR
      ) {
        Serial.println("Temporary DY50 error");
      }
      break;

    case WorkflowState::COMPLETE_AUTH: {
      if (!actionDue()) {
        break;
      }

      const StepResult result = completeAuthentication(
        currentRequest,
        currentRfidUid,
        currentFingerprintId,
        currentSessionId,
        currentChallenge
      );

      if (result == StepResult::SUCCESS) {
        Serial.println();
        Serial.println("================================");
        Serial.println(" STRONG AUTHENTICATION OK");
        Serial.println("================================");
        Serial.println("Remote signing in progress...");
        enterState(WorkflowState::SIGN_DOCUMENT);
      } else if (
        result == StepResult::TEMPORARY_ERROR
      ) {
        Serial.println("Complete temporarily unavailable, retrying");
        nextActionAt = millis() + RETRY_INTERVAL_MS;
      } else {
        beginDefinitiveFailure("AUTHENTICATION_REJECTED");
      }
      break;
    }

    case WorkflowState::SIGN_DOCUMENT: {
      if (!actionDue()) {
        break;
      }

      const StepResult result = signDocument(
        currentRequest,
        currentSessionId,
        completedSignatureId,
        completedAlgorithm
      );

      if (result == StepResult::SUCCESS) {
        enterState(WorkflowState::SUCCESS);
      } else if (
        result == StepResult::TEMPORARY_ERROR
      ) {
        Serial.println("Signing temporarily unavailable, retrying");
        nextActionAt = millis() + RETRY_INTERVAL_MS;
      } else {
        beginDefinitiveFailure("SIGNATURE_REJECTED");
      }
      break;
    }

    case WorkflowState::REPORT_FAILED: {
      if (!actionDue()) {
        break;
      }

      const StepResult result = reportRequestFailure(
        currentRequest.requestId,
        pendingFailureCode
      );

      if (result == StepResult::TEMPORARY_ERROR) {
        Serial.println("FAILED report temporarily unavailable, retrying");
        nextActionAt = millis() + RETRY_INTERVAL_MS;
      } else {
        Serial.println("Workflow ended in failure");
        clearWorkflow();
      }
      break;
    }

    case WorkflowState::SUCCESS:
      Serial.println();
      Serial.println("================================");
      Serial.println(" DOCUMENT SIGNED");
      Serial.println("================================");

      if (completedSignatureId.length() > 0) {
        Serial.print("Signature ID: ");
        Serial.println(completedSignatureId);
      }

      if (completedAlgorithm.length() > 0) {
        Serial.print("Algorithm: ");
        Serial.println(completedAlgorithm);
      }

      clearWorkflow();
      break;
  }
}


// ======================================================
// SETUP AND LOOP
// ======================================================

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("================================");
  Serial.println(" REMOTESIGN-LAB");
  Serial.println("================================");

  connectWiFi();

  if (WiFi.status() == WL_CONNECTED) {
    syncTime();
  }

  rfidReady = initializeRFID();
  fingerprintReady = initializeFingerprint();
  hardwareReady = rfidReady && fingerprintReady;

  if (WiFi.status() == WL_CONNECTED) {
    testServerConnection();
  }

  if (!hardwareReady) {
    Serial.println();
    Serial.println("Workflow suspended: incomplete hardware configuration.");
    Serial.println("No request will be claimed until both the RC522 and DY50");
    Serial.println("have been initialized.");
  } else {
    Serial.println();
    Serial.println("System ready - automatic polling");
  }

  lastPollAt = millis() - POLL_INTERVAL_MS;
}

void loop() {
  if (!hardwareReady) {
    delay(250);
    return;
  }

  processWorkflow();
  delay(20);
}
