#include <M5Cardputer.h>
#include <SPI.h>
#include <SD.h>
#include <mbedtls/sha256.h>
#include <WiFi.h>
#include <esp_bt.h>
#include <esp_wifi.h>
#include "wallet_core.h"

#define SD_SPI_SCK_PIN 40
#define SD_SPI_MISO_PIN 39
#define SD_SPI_MOSI_PIN 14
#define SD_SPI_CS_PIN 12
#define HID_UP 0x52
#define HID_DOWN 0x51
#define HID_RIGHT 0x4F
#define HID_LEFT 0x50

#define PAGE_FINGERPRINT 0
#define PAGE_MNEMONIC_FIRST 1
#define PAGE_MNEMONIC_COUNT 8
#define PAGE_PASSPHRASE 9
#define PAGE_ADDRESS 10
#define PAGE_SANITY 11
#define PAGE_SD 12
#define PAGE_COUNT 13

namespace {
constexpr uint16_t BG = 0x08AC, PANEL = 0x118F, PANEL2 = 0x19F3;
constexpr uint16_t CYAN = 0x07FF, MINT = 0x57F6, GOLD = 0xFEA0, ROSE = 0xF9B6;
constexpr uint16_t TEXT = 0xFFFF, MUTED = 0x9CF3, GREEN = 0x4FEA, RED = 0xF986;
constexpr size_t MAX_ROLLS = 1024;

// ---------------- secret / sensitive state (fixed buffers only) ----------------
char rolls[MAX_ROLLS];
size_t rollCount = 0;
char entropyHex[65];                     // audit fingerprint (public)
char passphrase[WC_PASSPHRASE_MAX_LEN] = {0};
char passphraseConfirm[WC_PASSPHRASE_MAX_LEN] = {0};
char passphraseNfkd[WC_PASSPHRASE_MAX_LEN] = {0};
char mnemonic[WC_MNEMONIC_MAX_LEN] = {0};
char address[WC_ADDRESS_MAX_LEN] = {0};
char quizBuf[12] = {0};
char tailBuf[25] = {0};
uint16_t wordOff[24] = {0};
uint8_t wordLen[24] = {0};
size_t passLen = 0, passLen1 = 0, quizLen = 0;
uint8_t quizPos[4] = {0};
uint8_t quizStep = 0;
bool passInput = false, passConfirmPhase = false;
bool quizActive = false, backupVerified = false;

// ---------------- UI / non-secret state ----------------
String statusLine = "READY: press one d6 key";
String lastAssessment = "";
uint16_t faceCount[6] = {0};
uint16_t vnBits = 0, ties = 0, maxStreak = 0;
uint32_t lastNavMs = 0, lastEnterMs = 0;
int resultPage = 0;
bool hasHash = false, showingResult = false, sdOK = false, clearArmed = false, lastReportOK = false, radiosOffOK = false;
bool waitingRelease = false;

// entropy mode fork (boot menu)
enum EntMode { MODE_VN = 0, MODE_RAW = 1, MODE_HYBRID = 2 };
EntMode entropyMode = MODE_VN;
bool modeSelect = true;
int modeCursor = 0;
// typed-input modes wait for full key release before processing any event
bool inputAwaitRelease = false;
constexpr char FW_VERSION[] = "0.3.0";
#ifndef FW_GIT_SHA
#define FW_GIT_SHA "unknown"
#endif

bool entropyReady() {
  switch (entropyMode) {
    case MODE_VN:     return vnBits >= 256;
    case MODE_RAW:
    case MODE_HYBRID: return rollCount == 100;  // exactly 100, one canonical transcript
  }
  return false;
}

// per-key edge state for typed input (passphrase / quiz)
uint32_t typeMask[WC_ASCII_BUCKETS] = {0, 0, 0, 0};
bool prevEnterK = false, prevDelK = false;

void wipeChars(volatile char* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = 0; }
void wipeBytes(volatile uint8_t* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = 0; }

void edgeReset() { memset(typeMask, 0, sizeof(typeMask)); prevEnterK = prevDelK = false; }

void keyEdges(const Keyboard_Class::KeysState& ks, WcKeyEdges& out) {
  wc_key_edges(reinterpret_cast<const uint8_t*>(ks.word.data()), ks.word.size(),
               ks.enter, ks.del, typeMask, &prevEnterK, &prevDelK, &out);
}

void fillRound(int x, int y, int w, int h, int r, uint16_t color) { M5Cardputer.Display.fillRoundRect(x, y, w, h, r, color); }
void textAt(int x, int y, const String& s, uint16_t fg = TEXT, uint16_t bg = BG, float size = 1) {
  M5Cardputer.Display.setTextSize(size);
  M5Cardputer.Display.setTextColor(fg, bg);
  M5Cardputer.Display.drawString(s, x, y);
}
void textAt(int x, int y, const char* s, uint16_t fg = TEXT, uint16_t bg = BG, float size = 1) {
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

// fills tailBuf with at most 24 most recent rolls (no Arduino String)
void rollTail(size_t n) {
  size_t start = rollCount > n ? rollCount - n : 0;
  size_t len = rollCount - start;
  if (len >= sizeof(tailBuf)) len = sizeof(tailBuf) - 1;
  memcpy(tailBuf, rolls + start, len);
  tailBuf[len] = 0;
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
  if (!entropyReady()) {
    w = entropyMode == MODE_VN ? "BLOCK: VN bits <256." : "BLOCK: need exactly 100 entries.";
    if (why) *why = w;
    return false;
  }
  if (entropyMode == MODE_HYBRID) {
    // dice are an auxiliary hedge only: face stats are informational, never
    // blocking. HWRNG is the primary source; its health check runs at build.
    if (why) *why = "HYBRID: 100 entries + SAR RNG. Dice fairness NOT required.";
    return true;
  }
  if (entropyMode == MODE_RAW) {
    uint8_t tmp[32];
    size_t r = wc_raw_extract(rolls, rollCount, tmp);
    wc_secure_zero(tmp, sizeof(tmp));
    if (r == WC_RAW_REJECTED) {
      w = "BLOCK: raw batch rejected, re-roll 100.";
      if (why) *why = w;
      return false;
    }
    w += "RAW MODE: dice bias kept. ";
  }
  if (rollCount < 520 && entropyMode == MODE_VN) w += "WARN low roll count. ";
  for (int i = 0; i < 6; ++i) if (faceCount[i] == 0) w += "WARN missing face " + String(i + 1) + ". ";
  if (maxStreak >= 8) w += "WARN long streak. ";
  float pairs = rollCount / 2.0f;
  float tieRate = pairs > 0 ? ties / pairs : 0;
  if (pairs >= 100 && (tieRate < 0.08f || tieRate > 0.27f)) w += "WARN tie rate unusual. ";
  if (why) *why = w.length() ? w : "SANITY OK: no simple anomaly. Not proof of randomness.";
  return true;
}

bool verifyRadios() {
  bool wifiOff = WiFi.getMode() == WIFI_OFF;
  auto btStatus = esp_bt_controller_get_status();
  bool btOff = btStatus != ESP_BT_CONTROLLER_STATUS_ENABLED;
  return wifiOff && btOff;
}

void drawHeader(bool full = true) {
  if (full) {
    M5Cardputer.Display.fillRect(0, 0, 240, 135, BG);
    for (int i = 0; i < 240; i += 8) M5Cardputer.Display.drawFastVLine(i, 0, 135, (i % 24 == 0) ? 0x0AEE : 0x09AD);
  }
  fillRound(4, 3, 232, 20, 6, PANEL2);
  M5Cardputer.Display.drawRoundRect(4, 3, 232, 20, 6, CYAN);
  textAt(12, 8, radiosOffOK ? "DICE ENTROPY // RADIOS OFF" : "RADIO STATE ERROR", radiosOffOK ? CYAN : RED, PANEL2);
  fillRound(210, 7, 18, 12, 3, showingResult ? GREEN : (sdOK ? MINT : GOLD));
}

// screen id for incremental redraw: full clear only when the screen changes,
// otherwise the same screen repaints its own solid panels (no black flash)
uint8_t drawnScreen = 0xFF;  // 0=menu 1=main 2=pass 3=quiz 4=result

void drawBars() {
  int baseX = 136, baseY = 42; label(baseX, 30, "d6 balance");
  for (int i = 0; i < 6; ++i) {
    int h = min<int>(44, faceCount[i]); int x = baseX + i * 15;
    M5Cardputer.Display.fillRect(x, baseY, 10, 48, 0x0B0F);
    M5Cardputer.Display.fillRoundRect(x, baseY + 46 - h, 10, h + 2, 3, (i % 2) ? MINT : CYAN);
    textAt(x + 2, 94, String(i + 1), MUTED, BG);
  }
}

void drawModeSelect() {
  drawHeader(drawnScreen != 0);
  drawnScreen = 0;
  fillRound(7, 29, 226, 66, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 29, 226, 66, 8, 0x3338);
  textAt(15, 37, "SELECT ENTROPY MODE", GOLD, PANEL);
  textAt(15, 49, modeCursor == 0 ? "> 1) Von Neumann" : "  1) Von Neumann", modeCursor == 0 ? CYAN : TEXT, PANEL);
  textAt(15, 60, modeCursor == 1 ? "> 2) Fair d6" : "  2) Fair d6", modeCursor == 1 ? CYAN : TEXT, PANEL);
  textAt(15, 71, modeCursor == 2 ? "> 3) Hybrid" : "  3) Hybrid", modeCursor == 2 ? CYAN : TEXT, PANEL);
  fillRound(7, 76, 226, 49, 6, PANEL2); M5Cardputer.Display.drawRoundRect(7, 76, 226, 49, 6, 0x3338);
  if (modeCursor == 0) {
    textAt(15, 81, "Rolls read in pairs; equal", TEXT, PANEL2);
    textAt(15, 93, "pairs dropped. Removes dice", TEXT, PANEL2);
    textAt(15, 105, "bias. ~615 rolls needed.", TEXT, PANEL2);
  } else if (modeCursor == 1) {
    textAt(15, 81, "100 rolls, exact base-6.", ROSE, PANEL2);
    textAt(15, 93, "Bias NOT corrected.", ROSE, PANEL2);
    textAt(15, 105, "Fair d6 only. Not recommended.", ROSE, PANEL2);
  } else {
    textAt(15, 81, "100 dice/1-6 entries hashed,", TEXT, PANEL2);
    textAt(15, 93, "plus ESP32-S3 physical RNG.", TEXT, PANEL2);
    textAt(15, 105, "Dice bias harmless here.", MINT, PANEL2);
  }
  textAt(15, 118, ";=up .=down  Enter: select", MUTED, BG);
  String idLine = String(FW_VERSION) + " " + String(FW_GIT_SHA);
  textAt(8, 126, idLine, MUTED, BG);
}

void drawMain() {
  showingResult = false;
  drawHeader(drawnScreen != 1);
  drawnScreen = 1;
  computeStats();
  fillRound(7, 29, 118, 66, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 29, 118, 66, 8, 0x3338);
  textAt(15, 37, "rolls", MUTED, PANEL); textAt(15, 50, String(rollCount), entropyReady() ? GREEN : GOLD, PANEL, 2);
  textAt(68, 50, entropyMode == MODE_VN ? "VN " + String(vnBits) + "/256"
                        : (entropyMode == MODE_RAW ? "RAW " + String(rollCount) + "/100"
                                                   : "HYB " + String(rollCount) + "/100"),
         entropyReady() ? GREEN : GOLD, PANEL);
  textAt(15, 75, "ties " + String(ties) + "  streak " + String(maxStreak), MUTED, PANEL);
  textAt(15, 86, sdOK ? "SD report enabled" : "SD not mounted", sdOK ? MINT : ROSE, PANEL);
  drawBars();
  fillRound(7, 103, 226, 27, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 103, 226, 27, 7, 0x3338);
  rollTail(24);
  textAt(15, 110, tailBuf[0] ? tailBuf : "press one key: 1..6", TEXT, PANEL2);
  textAt(15, 121, statusLine, hasHash ? GREEN : MUTED, PANEL2);
}

void drawPassInput() {
  drawHeader(drawnScreen != 2);
  drawnScreen = 2;
  fillRound(7, 29, 226, 66, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 29, 226, 66, 8, 0x3338);
  textAt(15, 37, passConfirmPhase ? "RE-ENTER (25th unique word)" : "BIP39 PASSPHRASE (25th unique word)", GOLD, PANEL);
  textAt(15, 51, "ASCII only, NFKD-normalized.", TEXT, PANEL);
  textAt(15, 63, "OPTIONAL: empty = default wallet.", GREEN, PANEL);
  textAt(15, 77, passConfirmPhase ? "Must match first entry." : "Entered twice, masked.", TEXT, PANEL);
  char maskBuf[WC_PASSPHRASE_MAX_LEN];
  size_t showLen = passLen < sizeof(maskBuf) - 1 ? passLen : sizeof(maskBuf) - 1;
  memset(maskBuf, '*', showLen); maskBuf[showLen] = 0;
  textAt(15, 90, showLen ? maskBuf : "<empty>", CYAN, BG);
  fillRound(7, 103, 226, 27, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 103, 226, 27, 7, 0x3338);
  textAt(15, 110, "len " + String(passLen) + "/" + String(WC_PASSPHRASE_MAX_LEN - 1), MUTED, PANEL2);
  textAt(15, 121, "Enter=confirm  Del=" + String(passLen ? "backspace" : (passConfirmPhase ? "edit" : "cancel")), TEXT, PANEL2);
}

void drawQuiz() {
  drawHeader(drawnScreen != 3);
  drawnScreen = 3;
  fillRound(7, 29, 226, 66, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 29, 226, 66, 8, 0x3338);
  textAt(15, 37, "BACKUP CHECK " + String(quizStep + 1) + "/4", GOLD, PANEL);
  textAt(15, 51, "Type word #" + String(quizPos[quizStep] + 1), TEXT, PANEL);
  textAt(15, 65, "then press Enter.", MUTED, PANEL);
  textAt(15, 81, quizBuf, CYAN, PANEL);
  fillRound(7, 103, 226, 27, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 103, 226, 27, 7, 0x3338);
  textAt(15, 110, statusLine, MUTED, PANEL2);
  textAt(15, 121, "Enter=check  Del=" + String(quizLen ? "backspace" : "cancel"), TEXT, PANEL2);
}

void drawResult() {
  showingResult = true;
  // result pages change layout per page: always full clear
  drawHeader();
  drawnScreen = 4;
  computeStats(); String why; bool ok = assessmentOK(&why);
  fillRound(8, 28, 224, 98, 10, PANEL); M5Cardputer.Display.drawRoundRect(8, 28, 224, 98, 10, ok ? GREEN : RED);
  textAt(18, 36, "page " + String(resultPage + 1) + "/" + String(PAGE_COUNT) + "  ;=up .=down  esc=back", MUTED, PANEL);
  if (resultPage == PAGE_FINGERPRINT) {
    textAt(18, 48, "1) SHA256 FINGERPRINT", GREEN, PANEL);
    M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setTextColor(CYAN, PANEL);
    char fl[20];
    snprintf(fl, sizeof(fl), "1|%.16s", entropyHex); M5Cardputer.Display.drawString(fl, 12, 61);
    snprintf(fl, sizeof(fl), "2|%.16s", entropyHex + 16); M5Cardputer.Display.drawString(fl, 12, 77);
    snprintf(fl, sizeof(fl), "3|%.16s", entropyHex + 32); M5Cardputer.Display.drawString(fl, 12, 93);
    snprintf(fl, sizeof(fl), "4|%.16s", entropyHex + 48); M5Cardputer.Display.drawString(fl, 12, 109);
  } else if (resultPage >= PAGE_MNEMONIC_FIRST && resultPage < PAGE_MNEMONIC_FIRST + PAGE_MNEMONIC_COUNT) {
    uint8_t base = (resultPage - PAGE_MNEMONIC_FIRST) * 3;
    textAt(18, 46, "MNEMONIC " + String(base + 1) + "-" + String(base + 3) + " / 24", GREEN, PANEL);
    for (int k = 0; k < 3; ++k) {
      uint16_t i = base + k;
      if (i >= 24) break;
      char wordLine[48];
      snprintf(wordLine, sizeof(wordLine), "%u. %.*s", i + 1, (int)wordLen[i], mnemonic + wordOff[i]);
      textAt(18, 60 + k * 14, wordLine, TEXT, PANEL);
      wc_secure_zero(wordLine, sizeof(wordLine));
    }
    textAt(18, 108, backupVerified ? "Backup verified." : "Write words down. Enter=check", backupVerified ? GREEN : ROSE, PANEL);
  } else if (resultPage == PAGE_PASSPHRASE) {
    textAt(18, 50, "3) PASSPHRASE", GOLD, PANEL);
    textAt(18, 64, passLen1 ? "set (never shown)" : "empty (default)", TEXT, PANEL);
    textAt(18, 78, "Changes every address.", TEXT, PANEL);
    textAt(18, 96, "Lose it => funds lost.", ROSE, PANEL);
    textAt(18, 108, "ASCII-only input.", MUTED, PANEL);
  } else if (resultPage == PAGE_ADDRESS) {
    if (!backupVerified) {
      textAt(18, 46, "4) SOLANA ADDRESS", CYAN, PANEL);
      textAt(18, 62, "LOCKED - verify backup first.", ROSE, PANEL);
      textAt(18, 76, "Go to mnemonic pages,", TEXT, PANEL);
      textAt(18, 88, "press Enter, type 4 words.", TEXT, PANEL);
    } else {
      textAt(18, 46, "4) SOLANA ADDRESS", CYAN, PANEL);
      char al[17];
      snprintf(al, sizeof(al), "%.16s", address); textAt(18, 60, al, TEXT, PANEL);
      snprintf(al, sizeof(al), "%.16s", address + 16); textAt(18, 72, al, TEXT, PANEL);
      snprintf(al, sizeof(al), "%.16s", address + 32); textAt(18, 84, al, TEXT, PANEL);
      textAt(18, 102, "Path m/44'/501'/0'/0'", MUTED, PANEL);
      textAt(18, 112, passLen1 ? "passphrase restore: verify" : "Phantom path-compatible", passLen1 ? ROSE : MUTED, PANEL);
    }
  } else if (resultPage == PAGE_SANITY) {
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
  f.println("firmware_version=" + String(FW_VERSION));
  f.println("firmware_git_sha=" + String(FW_GIT_SHA));
  f.println("rolls=" + String(rollCount));
  if (entropyMode == MODE_VN) {
    f.println("entropy_mode=von_neumann");
    f.println("vn_bits=" + String(vnBits));
    f.println("ties=" + String(ties));
    f.println("used_vn_bits=256");
    f.println("surplus_vn_bits=" + String(vnBits > 256 ? vnBits - 256 : 0));
  } else if (entropyMode == MODE_RAW) {
    f.println("entropy_mode=raw_dice");
    f.println("raw_dice_rolls=100");
    f.println("raw_dice_conversion=exact_uniform_rejection (X >= 5*2^256 rejected)");
    f.println("raw_dice_acceptance_probability=~88.6% (fair dice)");
    f.println("raw_dice_contract=FAIR INDEPENDENT D6 ONLY - bias not corrected");
  } else {
    f.println("entropy_mode=hybrid");
    f.println("hybrid_dice_rolls=100");
    f.println("hybrid_dice_conditioner=sha256");
    f.println("hybrid_hwrng=esp32s3_sar_rng");
    f.println("hybrid_hwrng_sample_bytes=512");
    f.println("hybrid_combiner=xor");
    f.println("hybrid_domain_version=1");
    f.println("roll_transcript_saved=false");
    f.println("hwrng_samples_saved=false");
    f.println("source_digests_saved=false");
  }
  f.println("max_streak=" + String(maxStreak));
  f.println("faces=" + String(faceCount[0]) + "," + String(faceCount[1]) + "," + String(faceCount[2]) + "," + String(faceCount[3]) + "," + String(faceCount[4]) + "," + String(faceCount[5]));
  f.println("audit_fingerprint_sha256=" + String(entropyHex));
  // address is gated on backup verification: never written to SD before the quiz passes
  f.println(backupVerified ? ("address=" + String(address[0] ? address : "n/a")) : "address=n/a (backup not verified)");
  f.println(passLen1 > 0 ? "passphrase_set=yes" : "passphrase_set=no");
  f.println("passphrase_ascii_only=yes");
  f.println(backupVerified ? "backup_verified=yes" : "backup_verified=no");
  f.println("roll_transcript_saved=false");
  f.println("raw_vn_entropy_saved=false");
  f.println("mnemonic_saved=false");
  f.println("private_key_saved=false");
  f.flush();
  lastReportOK = !f.getWriteError();
  f.close();
}

void parseMnemonicWords() {
  uint16_t w = 0; wordOff[0] = 0;
  for (size_t i = 0; mnemonic[i]; ++i) {
    if (mnemonic[i] == ' ') {
      wordLen[w] = (uint8_t)(i - wordOff[w]);
      w++;
      if (w < 24) wordOff[w] = (uint16_t)(i + 1);
    }
  }
  if (w < 24) wordLen[w] = (uint8_t)(strlen(mnemonic) - wordOff[w]);
}

void buildWallet() {
  if (!verifyRadios()) {
    radiosOffOK = false; hasHash = false;
    statusLine = "RADIO STATE ERROR - blocked";
    drawMain();
    return;
  }
  String why; bool ok = assessmentOK(&why);
  if (!ok) {
    hasHash = false;
    statusLine = entropyMode == MODE_VN ? "need 256 VN bits" : "need exactly 100 entries";
    entropyHex[0] = 0; resultPage = PAGE_SANITY; lastAssessment = why;
    writeReport(false, why);
    drawResult();
    return;
  }

  // one and only one bytes[32] handoff into BIP39, regardless of mode
  uint8_t bytes[32];
  switch (entropyMode) {
    case MODE_VN:
      if (wc_vn_extract(rolls, rollCount, bytes) < 256) {
        statusLine = "need 256 VN bits"; hasHash = false; drawMain(); return;
      }
      break;
    case MODE_RAW:
      if (wc_raw_extract(rolls, rollCount, bytes) != 256) {
        statusLine = "raw batch rejected: clear + re-roll"; hasHash = false;
        wipeBytes(bytes, 32); drawMain(); return;
      }
      break;
    case MODE_HYBRID: {
      uint8_t diceD[32] = {0}, hwD[32] = {0};
      if (!wc_hybrid_dice_digest(rolls, rollCount, diceD)) {
        statusLine = "hybrid: dice transcript invalid";
        hasHash = false;
        wipeBytes(diceD, 32);
        drawMain();
        return;
      }
      if (!verifyRadios()) {
        radiosOffOK = false; hasHash = false;
        statusLine = "RADIO STATE ERROR - blocked";
        wipeBytes(diceD, 32);
        drawMain();
        return;
      }
      // HWRNG collected at the last possible moment, inside the radio-
      // verified critical section. Catastrophic failure blocks generation.
      if (!wc_platform_hwrng_digest(hwD)) {
        hasHash = false;
        statusLine = "HWRNG FAILURE - BLOCKED";
        wipeBytes(hwD, 32);
        wipeBytes(diceD, 32);
        drawMain();
        return;
      }
      wc_hybrid_combine(hwD, diceD, bytes);
      wc_secure_zero(hwD, sizeof(hwD));
      wc_secure_zero(diceD, sizeof(diceD));
      break;
    }
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
  const char* hx = "0123456789abcdef";
  for (int i = 0; i < 32; ++i) { entropyHex[i * 2] = hx[hash[i] >> 4]; entropyHex[i * 2 + 1] = hx[hash[i] & 15]; }
  entropyHex[64] = 0;

  // deterministic backup-quiz positions from the audit fingerprint
  wc_quiz_positions(hash, quizPos);

  if (!wc_nfkd(passphrase, passphraseNfkd, sizeof(passphraseNfkd))) {
    statusLine = "passphrase not valid UTF-8";
    passInput = true; hasHash = false;
    drawPassInput();
    return;
  }
  wc_mnemonic_from_entropy(bytes, mnemonic);
  parseMnemonicWords();
  uint8_t seed[64];
  wc_seed_from_mnemonic(mnemonic, passphraseNfkd, seed);
  wc_solana_address(seed, address);
  wipeBytes(seed, 64);
  wipeBytes(bytes, 32);
  // passphrase material is no longer needed once the seed is derived:
  // keep only the set/empty flag (passLen1) for display and audit
  wipeChars(passphrase, sizeof(passphrase));
  wipeChars(passphraseConfirm, sizeof(passphraseConfirm));
  wipeChars(passphraseNfkd, sizeof(passphraseNfkd));
  wipeBytes(hash, 32);

  passInput = false;
  backupVerified = false;
  quizActive = false;
  quizStep = 0;
  quizLen = 0;
  memset(quizBuf, 0, sizeof(quizBuf));
  waitingRelease = true;
  hasHash = true; statusLine = "backup: verify words (Enter)"; resultPage = PAGE_FINGERPRINT; lastAssessment = why;
  writeReport(true, why); drawResult();
}

void startPassphrase() {
  wipeChars(passphrase, sizeof(passphrase));
  wipeChars(passphraseConfirm, sizeof(passphraseConfirm));
  passLen = 0; passLen1 = 0;
  passConfirmPhase = false;
  edgeReset();
  inputAwaitRelease = true;  // the Enter that opened this screen must be released first
  passInput = true; showingResult = false; hasHash = false; clearArmed = false;
  statusLine = "passphrase: Enter=confirm";
  drawPassInput();
}

void handleModeSelect(const Keyboard_Class::KeysState& ks) {
  bool prev = false, next = false;
  for (auto h : ks.hid_keys) {
    if (h == HID_UP || h == HID_LEFT) prev = true;
    if (h == HID_DOWN || h == HID_RIGHT) next = true;
  }
  for (auto c : ks.word) {
    if (c == 'w' || c == 'a' || c == 'W' || c == 'A' || c == ';' || c == ',') prev = true;
    if (c == 's' || c == 'd' || c == 'S' || c == 'D' || c == '.' || c == '/') next = true;
  }
  if (prev || next) { modeCursor = (modeCursor + (next ? 1 : 2)) % 3; drawModeSelect(); return; }
  if (ks.enter) {
    entropyMode = (EntMode)modeCursor;
    modeSelect = false;
    if (entropyMode == MODE_VN) statusLine = "mode: Von Neumann";
    else if (entropyMode == MODE_RAW) statusLine = "mode: fair d6 - bias kept";
    else statusLine = "mode: hybrid (HWRNG + dice)";
    drawMain();
    return;
  }
}

void handlePassInput(const Keyboard_Class::KeysState& ks) {
  WcKeyEdges e; keyEdges(ks, e);
  if (e.enter) {
    if (passConfirmPhase) {
      if (wc_ct_equal(passphrase, passphraseConfirm, WC_PASSPHRASE_MAX_LEN)) {
        passLen = passLen1;
        passInput = false;
        buildWallet();
        return;
      }
      wipeChars(passphrase, sizeof(passphrase));
      wipeChars(passphraseConfirm, sizeof(passphraseConfirm));
      passLen = 0; passLen1 = 0; passConfirmPhase = false;
      statusLine = "MISMATCH - enter again";
      drawPassInput();
      return;
    }
    if (passLen == 0) { passInput = false; passLen1 = 0; buildWallet(); return; }
    passLen1 = passLen; passLen = 0;
    passConfirmPhase = true;
    statusLine = "re-enter to confirm";
    drawPassInput();
    return;
  }
  if (e.del) {
    char* buf = passConfirmPhase ? passphraseConfirm : passphrase;
    if (passLen) { buf[--passLen] = 0; statusLine = "char erased"; drawPassInput(); return; }
    if (passConfirmPhase) { passConfirmPhase = false; passLen = passLen1; statusLine = "edit first entry"; drawPassInput(); return; }
    passInput = false; waitingRelease = true; statusLine = "passphrase cancelled"; drawMain(); return;
  }
  if (e.addedCount == 1) {
    char* buf = passConfirmPhase ? passphraseConfirm : passphrase;
    if (passLen < WC_PASSPHRASE_MAX_LEN - 1) { buf[passLen++] = e.added[0]; statusLine = "passphrase updated"; }
    else statusLine = "passphrase too long";
    drawPassInput();
    return;
  }
  if (e.chord) { statusLine = "one key at a time"; drawPassInput(); return; }
}

void handleQuiz(const Keyboard_Class::KeysState& ks) {
  WcKeyEdges e; keyEdges(ks, e);
  if (e.enter) {
    uint8_t pos = quizPos[quizStep];
    bool match = quizLen == wordLen[pos] && memcmp(quizBuf, mnemonic + wordOff[pos], wordLen[pos]) == 0;
    if (!match) {
      quizStep = 0; quizLen = 0; memset(quizBuf, 0, sizeof(quizBuf));
      statusLine = "WRONG - re-check your backup";
      drawQuiz();
      return;
    }
    quizStep++; quizLen = 0; memset(quizBuf, 0, sizeof(quizBuf));
    if (quizStep == 4) {
      quizActive = false; backupVerified = true; waitingRelease = true;
      statusLine = "BACKUP VERIFIED";
      drawResult();
      String why; bool ok = assessmentOK(&why);
      writeReport(ok, "BACKUP VERIFIED: " + why);
      return;
    }
    statusLine = "correct - next word";
    drawQuiz();
    return;
  }
  if (e.del) {
    if (quizLen) { quizBuf[--quizLen] = 0; statusLine = "char erased"; }
    else { quizActive = false; waitingRelease = true; statusLine = "backup check cancelled"; drawResult(); return; }
    drawQuiz();
    return;
  }
  if (e.addedCount == 1) {
    char c = e.added[0];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (c >= 'a' && c <= 'z' && quizLen < sizeof(quizBuf) - 1) { quizBuf[quizLen++] = c; }
    drawQuiz();
    return;
  }
  if (e.chord) { statusLine = "one key at a time"; drawQuiz(); return; }
}

void acceptRoll(char c) {
  if (c < '1' || c > '6') return;
  if ((entropyMode == MODE_RAW || entropyMode == MODE_HYBRID) && rollCount >= 100) {
    statusLine = "100 rolls complete"; drawMain(); return;
  }
  if (rollCount >= MAX_ROLLS) { statusLine = "max roll buffer reached"; drawMain(); return; }
  rolls[rollCount++] = c;
  hasHash = false;
  clearArmed = false;
  statusLine = "roll accepted; release key";
  drawMain();
}

void clearEverything() {
  wipeRolls();
  wipeChars(tailBuf, sizeof(tailBuf));
  wipeChars(passphrase, sizeof(passphrase));
  wipeChars(passphraseConfirm, sizeof(passphraseConfirm));
  wipeChars(passphraseNfkd, sizeof(passphraseNfkd));
  wipeChars(mnemonic, sizeof(mnemonic));
  wipeChars(address, sizeof(address));
  memset(quizBuf, 0, sizeof(quizBuf));
  passLen = 0; passLen1 = 0; quizLen = 0;
  passInput = false; passConfirmPhase = false;
  quizActive = false; backupVerified = false;
  entropyHex[0] = 0;
  hasHash = false;
  showingResult = false;
  clearArmed = false;
  waitingRelease = false;
  edgeReset();
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
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  btStop();
  esp_bt_controller_disable();
}

void setup() {
  auto cfg = M5.config(); M5Cardputer.begin(cfg, true); M5Cardputer.Display.setRotation(1); M5Cardputer.Display.setFont(&fonts::Font0);
  disableRadios();
  radiosOffOK = verifyRadios();
  wipeRolls();
  initSD();
  statusLine = "select entropy mode";
  drawModeSelect();
}

void loop() {
  M5Cardputer.update();
  bool pressed = M5Cardputer.Keyboard.isPressed();
  Keyboard_Class::KeysState ks = M5Cardputer.Keyboard.keysState();
  if (!pressed) { waitingRelease = false; edgeReset(); inputAwaitRelease = false; return; }
  if (modeSelect) {
    if (waitingRelease) return;
    waitingRelease = true;
    handleModeSelect(ks);
    return;
  }
  if (passInput || quizActive) {
    if (inputAwaitRelease) return;  // ignore the keypress that opened this mode
    if (passInput) handlePassInput(ks);
    else handleQuiz(ks);
    return;
  }
  if (waitingRelease) return;
  waitingRelease = true;

  bool yes = false, no = false, prev = false, next = false, esc = false;
  int diceCount = 0; char dice = 0;
  for (auto h : ks.hid_keys) {
    if (h == HID_UP || h == HID_LEFT) prev = true;
    if (h == HID_DOWN || h == HID_RIGHT) next = true;
  }
  for (auto c : ks.word) {
    if (c == 'y' || c == 'Y') yes = true;
    if (c == 'n' || c == 'N') no = true;
    // Cardputer has no dedicated arrow keys: ';' '.' ',' '/' carry the
    // arrow glyphs and arrive as word chars, never as HID arrow codes
    if (c == 'w' || c == 'a' || c == 'W' || c == 'A' || c == ';' || c == ',') prev = true;
    if (c == 's' || c == 'd' || c == 'S' || c == 'D' || c == '.' || c == '/') next = true;
    if (c == '`') esc = true;  // Esc key on Cardputer
    if (c >= '1' && c <= '6') { dice = c; diceCount++; }
  }

  if (clearArmed) {
    if (yes) clearEverything();
    else if (no) { clearArmed = false; statusLine = "clear cancelled"; drawResult(); }
    else { statusLine = "Confirm clear: Y or N"; drawResult(); }
    return;
  }

  if (showingResult && diceCount == 1 && !prev && !next) { acceptRoll(dice); return; }

  if (showingResult && esc) { statusLine = "back to rolls"; drawMain(); return; }

  uint32_t now = millis();
  if (showingResult && (prev || next) && now - lastNavMs > 180) {
    resultPage = prev ? (resultPage + PAGE_COUNT - 1) % PAGE_COUNT : (resultPage + 1) % PAGE_COUNT;
    lastNavMs = now;
    drawResult();
    return;
  }

  if (showingResult && ks.enter && now - lastEnterMs > 500 &&
      resultPage >= PAGE_MNEMONIC_FIRST && resultPage < PAGE_MNEMONIC_FIRST + PAGE_MNEMONIC_COUNT) {
    lastEnterMs = now;
    if (!backupVerified) {
      quizActive = true; quizStep = 0; quizLen = 0;
      memset(quizBuf, 0, sizeof(quizBuf));
      edgeReset();
      inputAwaitRelease = true;  // the Enter that opened the quiz must be released first
      statusLine = "type the word shown";
      drawQuiz();
    }
    return;
  }

  if (ks.del) {
    if (showingResult || hasHash) { clearArmed = true; statusLine = "Clear all? press Y/N"; drawResult(); return; }
    if (rollCount) { rolls[--rollCount] = 0; statusLine = "last roll erased"; }
    drawMain();
    return;
  }

  if (ks.enter && now - lastEnterMs > 500) {
    lastEnterMs = now;
    if (entropyReady()) {
      if (!verifyRadios()) {
        radiosOffOK = false;
        statusLine = "RADIO STATE ERROR - blocked";
        drawMain();
        return;
      }
      startPassphrase();
    } else {
      buildWallet();
    }
    return;
  }

  if (!showingResult && diceCount == 1) acceptRoll(dice);
  else if (!showingResult && diceCount > 1) { statusLine = "ignored chord; press one key"; drawMain(); }
}
