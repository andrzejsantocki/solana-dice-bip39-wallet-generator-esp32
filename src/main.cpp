#include <M5Cardputer.h>
#include <SPI.h>
#include <SD.h>
#include <mbedtls/sha256.h>
#include <WiFi.h>
#include <esp_bt.h>
#include <esp_wifi.h>

#define SD_SPI_SCK_PIN 40
#define SD_SPI_MISO_PIN 39
#define SD_SPI_MOSI_PIN 14
#define SD_SPI_CS_PIN 12
#define HID_UP 0x52
#define HID_DOWN 0x51
#define HID_RIGHT 0x4F
#define HID_LEFT 0x50

namespace {
constexpr uint16_t BG = 0x08AC, PANEL = 0x118F, PANEL2 = 0x19F3;
constexpr uint16_t CYAN = 0x07FF, MINT = 0x57F6, GOLD = 0xFEA0, ROSE = 0xF9B6;
constexpr uint16_t TEXT = 0xFFFF, MUTED = 0x9CF3, GREEN = 0x4FEA, RED = 0xF986;
constexpr size_t MAX_ROLLS = 1024;

char rolls[MAX_ROLLS];
size_t rollCount = 0;
String entropyHex;
String statusLine = "READY: press one d6 key";
String lastAssessment = "";
uint16_t faceCount[6] = {0};
uint16_t vnBits = 0, ties = 0, maxStreak = 0;
uint32_t lastNavMs = 0, lastEnterMs = 0;
int resultPage = 0;
bool hasHash = false, showingResult = false, sdOK = false, clearArmed = false, lastReportOK = false, radiosOffOK = false;
bool waitingRelease = false;

void fillRound(int x, int y, int w, int h, int r, uint16_t color) { M5Cardputer.Display.fillRoundRect(x, y, w, h, r, color); }
void textAt(int x, int y, const String& s, uint16_t fg = TEXT, uint16_t bg = BG, float size = 1) {
  M5Cardputer.Display.setTextSize(size);
  M5Cardputer.Display.setTextColor(fg, bg);
  M5Cardputer.Display.drawString(s, x, y);
}
void label(int x, int y, const String& s) { textAt(x, y, s, MUTED, BG); }

void wipeRolls() {
  volatile char* p = rolls;
  for (size_t i = 0; i < MAX_ROLLS; ++i) p[i] = 0;
  rollCount = 0;
}

String rollTail(size_t n) {
  String out;
  size_t start = rollCount > n ? rollCount - n : 0;
  out.reserve(rollCount - start);
  for (size_t i = start; i < rollCount; ++i) out += rolls[i];
  return out;
}

void computeStats() {
  memset(faceCount, 0, sizeof(faceCount));
  vnBits = 0; ties = 0; maxStreak = 0;
  char prev = 0; uint16_t streak = 0;
  for (size_t i = 0; i < rollCount; ++i) {
    char c = rolls[i];
    if (c >= '1' && c <= '6') faceCount[c - '1']++;
    if (c == prev) streak++; else { prev = c; streak = 1; }
    if (streak > maxStreak) maxStreak = streak;
  }
  for (size_t i = 1; i < rollCount; i += 2) {
    char a = rolls[i - 1], b = rolls[i];
    if (a == b) ties++; else vnBits++;
  }
}

bool assessmentOK(String* why = nullptr) {
  computeStats();
  String w = "";
  if (vnBits < 256) {
    w = "BLOCK: VN bits <256.";
    if (why) *why = w;
    return false;
  }
  if (rollCount < 520) w += "WARN low roll count. ";
  for (int i = 0; i < 6; ++i) if (faceCount[i] == 0) w += "WARN missing face " + String(i + 1) + ". ";
  if (maxStreak >= 8) w += "WARN long streak. ";
  float pairs = rollCount / 2.0f;
  float tieRate = pairs > 0 ? ties / pairs : 0;
  if (pairs >= 100 && (tieRate < 0.08f || tieRate > 0.27f)) w += "WARN tie rate unusual. ";
  if (why) *why = w.length() ? w : "SANITY OK: no simple anomaly. Not proof of randomness.";
  return true;
}

void drawHeader() {
  M5Cardputer.Display.fillRect(0, 0, 240, 135, BG);
  for (int i = 0; i < 240; i += 8) M5Cardputer.Display.drawFastVLine(i, 0, 135, (i % 24 == 0) ? 0x0AEE : 0x09AD);
  fillRound(4, 3, 232, 20, 6, PANEL2);
  M5Cardputer.Display.drawRoundRect(4, 3, 232, 20, 6, CYAN);
  textAt(12, 8, radiosOffOK ? "DICE ENTROPY // RADIOS OFF" : "RADIO STATE ERROR", radiosOffOK ? CYAN : RED, PANEL2);
  fillRound(210, 7, 18, 12, 3, showingResult ? GREEN : (sdOK ? MINT : GOLD));
}

void drawBars() {
  computeStats(); int baseX = 136, baseY = 42; label(baseX, 30, "d6 balance");
  for (int i = 0; i < 6; ++i) {
    int h = min<int>(44, faceCount[i]); int x = baseX + i * 15;
    M5Cardputer.Display.fillRect(x, baseY, 10, 48, 0x0B0F);
    M5Cardputer.Display.fillRoundRect(x, baseY + 46 - h, 10, h + 2, 3, (i % 2) ? MINT : CYAN);
    textAt(x + 2, 94, String(i + 1), MUTED, BG);
  }
}

void drawMain() {
  showingResult = false;
  drawHeader(); computeStats();
  fillRound(7, 29, 118, 66, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 29, 118, 66, 8, 0x3338);
  textAt(15, 37, "rolls", MUTED, PANEL); textAt(15, 50, String(rollCount), vnBits >= 256 ? GREEN : GOLD, PANEL, 2);
  textAt(68, 50, "VN " + String(vnBits) + "/256", vnBits >= 256 ? GREEN : GOLD, PANEL);
  textAt(15, 75, "ties " + String(ties) + "  streak " + String(maxStreak), MUTED, PANEL);
  textAt(15, 86, sdOK ? "SD report enabled" : "SD not mounted", sdOK ? MINT : ROSE, PANEL);
  drawBars();
  fillRound(7, 103, 226, 27, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 103, 226, 27, 7, 0x3338);
  String tail = rollTail(24);
  textAt(15, 110, tail.length() ? tail : "press one key: 1..6", TEXT, PANEL2);
  textAt(15, 121, statusLine, hasHash ? GREEN : MUTED, PANEL2);
}

void drawResult() {
  showingResult = true;
  drawHeader(); computeStats(); String why; bool ok = assessmentOK(&why);
  fillRound(8, 28, 224, 98, 10, PANEL); M5Cardputer.Display.drawRoundRect(8, 28, 224, 98, 10, ok ? GREEN : RED);
  textAt(18, 36, "page " + String(resultPage + 1) + "/6  arrows up/down", MUTED, PANEL);
  if (resultPage == 0) {
    textAt(18, 48, "1) SHA256 FINGERPRINT", GREEN, PANEL);
    M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setTextColor(CYAN, PANEL);
    M5Cardputer.Display.drawString("1|" + entropyHex.substring(0, 16), 12, 61);
    M5Cardputer.Display.drawString("2|" + entropyHex.substring(16, 32), 12, 77);
    M5Cardputer.Display.drawString("3|" + entropyHex.substring(32, 48), 12, 93);
    M5Cardputer.Display.drawString("4|" + entropyHex.substring(48, 64), 12, 109);
  } else if (resultPage == 1) {
    textAt(18, 50, "2) PASSPHRASE", GOLD, PANEL);
    textAt(18, 64, "Optional BIP39 passphrase.", TEXT, PANEL);
    textAt(18, 78, "Changes every address.", TEXT, PANEL);
    textAt(18, 96, "Lose it => funds lost.", ROSE, PANEL);
    textAt(18, 108, "Default empty for restore.", MUTED, PANEL);
  } else if (resultPage == 2) {
    textAt(18, 50, "3) SOLFLARE / PHANTOM", CYAN, PANEL);
    textAt(18, 64, "Path m/44'/501'/0'/0'", TEXT, PANEL);
    textAt(18, 78, "Restore: words + passphrase.", TEXT, PANEL);
    textAt(18, 96, "Empty passphrase common.", MUTED, PANEL);
    textAt(18, 108, "Address derivation next.", MUTED, PANEL);
  } else if (resultPage == 3) {
    textAt(18, 50, "4) MNEMONIC / SEED", GREEN, PANEL);
    textAt(18, 64, "Main human backup.", TEXT, PANEL);
    textAt(18, 78, "24 words restore wallet.", TEXT, PANEL);
    textAt(18, 96, "Not implemented yet here.", ROSE, PANEL);
    textAt(18, 108, "Next build adds BIP39.", MUTED, PANEL);
  } else if (resultPage == 4) {
    textAt(18, 50, ok ? "5) SANITY: OK" : "5) SANITY: BLOCK", ok ? GREEN : RED, PANEL);
    textAt(18, 64, why.substring(0, 34), ok ? GREEN : ROSE, PANEL);
    textAt(18, 76, why.substring(34, 68), ok ? GREEN : ROSE, PANEL);
    textAt(18, 100, ok ? "Warnings are not proof." : "Blocked: add more rolls.", ROSE, PANEL);
  } else {
    textAt(18, 50, "6) SD / AUDIT", sdOK ? MINT : ROSE, PANEL);
    textAt(18, 64, sdOK ? (lastReportOK ? "report write OK" : "report not written") : "SD unavailable", lastReportOK ? GREEN : ROSE, PANEL);
    textAt(18, 78, "/dice_wallet/report.txt", TEXT, PANEL);
    textAt(18, 92, "Report excludes secrets.", ROSE, PANEL);
    textAt(18, 108, clearArmed ? "Y=yes N=no clear all" : "Del arms clear", MUTED, PANEL);
  }
}

void writeReport(bool ok, const String& why) {
  lastReportOK = false;
  if (!sdOK) return;
  SD.mkdir("/dice_wallet");
  File f = SD.open("/dice_wallet/report.txt", FILE_APPEND);
  if (!f) return;
  f.println("--- dice entropy sanity report ---");
  f.println(ok ? "SANITY_OK" : "SANITY_BLOCK");
  f.println(why);
  f.println("rolls=" + String(rollCount));
  f.println("vn_bits=" + String(vnBits));
  f.println("ties=" + String(ties));
  f.println("max_streak=" + String(maxStreak));
  f.println("faces=" + String(faceCount[0]) + "," + String(faceCount[1]) + "," + String(faceCount[2]) + "," + String(faceCount[3]) + "," + String(faceCount[4]) + "," + String(faceCount[5]));
  f.println("audit_fingerprint_sha256=" + entropyHex);
  f.println("roll_transcript_saved=false");
  f.println("raw_vn_entropy_saved=false");
  f.println("used_vn_bits=256");
  f.println("surplus_vn_bits=" + String(vnBits > 256 ? vnBits - 256 : 0));
  f.flush();
  lastReportOK = !f.getWriteError();
  f.close();
}

void makeEntropy() {
  String why; bool ok = assessmentOK(&why);
  if (!ok) { hasHash = false; statusLine = "need 256 VN bits"; entropyHex = ""; resultPage = 4; lastAssessment = why; writeReport(false, why); drawResult(); return; }

  uint8_t bytes[32] = {0}; uint16_t bit = 0;
  for (size_t i = 1; i < rollCount && bit < 256; i += 2) {
    char a = rolls[i - 1], b = rolls[i]; if (a == b) continue;
    if (a > b) bytes[bit / 8] |= (1 << (7 - (bit % 8)));
    bit++;
  }
  uint8_t hash[32];
  const char domain[] = "DiceWallet audit v1";
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char*>(domain), sizeof(domain) - 1);
  mbedtls_sha256_update(&ctx, bytes, 32);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  entropyHex = ""; const char* hx = "0123456789abcdef";
  for (uint8_t b : hash) { entropyHex += hx[b >> 4]; entropyHex += hx[b & 15]; }
  volatile uint8_t* wipeBytes = bytes;
  volatile uint8_t* wipeHash = hash;
  for (size_t i = 0; i < sizeof(bytes); ++i) wipeBytes[i] = 0;
  for (size_t i = 0; i < sizeof(hash); ++i) wipeHash[i] = 0;
  hasHash = true; statusLine = "audit fingerprint ready"; resultPage = 0; lastAssessment = why; writeReport(true, why); drawResult();
}

void acceptRoll(char c) {
  if (c < '1' || c > '6') return;
  if (rollCount >= MAX_ROLLS) { statusLine = "max roll buffer reached"; drawMain(); return; }
  rolls[rollCount++] = c;
  hasHash = false;
  clearArmed = false;
  statusLine = "roll accepted; release key";
  drawMain();
}

void clearEverything() {
  wipeRolls();
  entropyHex = "";
  hasHash = false;
  showingResult = false;
  clearArmed = false;
  waitingRelease = false;
  statusLine = "cleared";
  resultPage = 0;
  drawMain();
}

void initSD() {
  SPI.begin(SD_SPI_SCK_PIN, SD_SPI_MISO_PIN, SD_SPI_MOSI_PIN, SD_SPI_CS_PIN);
  sdOK = SD.begin(SD_SPI_CS_PIN, SPI, 25000000) && SD.cardType() != CARD_NONE;
}
}  // namespace

void disableRadios() {
  WiFi.disconnect(true, true);
  bool wifiModeOff = WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  btStop();
  esp_bt_controller_disable();
  auto btStatus = esp_bt_controller_get_status();
  radiosOffOK = wifiModeOff && WiFi.getMode() == WIFI_OFF && btStatus != ESP_BT_CONTROLLER_STATUS_ENABLED;
}

void setup() {
  disableRadios();
  auto cfg = M5.config(); M5Cardputer.begin(cfg, true); M5Cardputer.Display.setRotation(1); M5Cardputer.Display.setFont(&fonts::Font0);
  wipeRolls();
  initSD(); drawMain();
}

void loop() {
  M5Cardputer.update();
  bool pressed = M5Cardputer.Keyboard.isPressed();
  if (!pressed) { waitingRelease = false; return; }
  if (waitingRelease) return;

  Keyboard_Class::KeysState ks = M5Cardputer.Keyboard.keysState();
  waitingRelease = true;

  bool yes = false, no = false, prev = false, next = false;
  int diceCount = 0; char dice = 0;
  for (auto h : ks.hid_keys) {
    if (h == HID_UP || h == HID_LEFT) prev = true;
    if (h == HID_DOWN || h == HID_RIGHT) next = true;
  }
  for (auto c : ks.word) {
    if (c == 'y' || c == 'Y') yes = true;
    if (c == 'n' || c == 'N') no = true;
    if (c == 'w' || c == 'a' || c == 'W' || c == 'A') prev = true;
    if (c == 's' || c == 'd' || c == 'S' || c == 'D') next = true;
    if (c >= '1' && c <= '6') { dice = c; diceCount++; }
  }

  if (clearArmed) {
    if (yes) clearEverything();
    else if (no) { clearArmed = false; statusLine = "clear cancelled"; drawResult(); }
    else { statusLine = "Confirm clear: Y or N"; drawResult(); }
    return;
  }

  uint32_t now = millis();
  if (showingResult && (prev || next) && now - lastNavMs > 180) {
    resultPage = prev ? (resultPage + 5) % 6 : (resultPage + 1) % 6;
    lastNavMs = now;
    drawResult();
    return;
  }

  if (ks.del) {
    if (showingResult || hasHash) { clearArmed = true; statusLine = "Clear all? press Y/N"; drawResult(); return; }
    if (rollCount) { rolls[--rollCount] = 0; statusLine = "last roll erased"; }
    drawMain();
    return;
  }

  if (ks.enter && now - lastEnterMs > 500) { lastEnterMs = now; makeEntropy(); return; }

  if (!showingResult && diceCount == 1) acceptRoll(dice);
  else if (!showingResult && diceCount > 1) { statusLine = "ignored chord; press one key"; drawMain(); }
}
