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
#define PAGE_MNEMONIC_COUNT 4   // 6 words per page
#define PAGE_ADDRESS 5
#define PAGE_SANITY 6
#define PAGE_SD 7
#define PAGE_COUNT 8

namespace {
// Light "web3" palette: quiet neutral surfaces, ink-dark copy and saturated
// violet/cyan accents.  Keeping the background bright also improves legibility
// on the Cardputer's small display in daylight.
constexpr uint16_t BG = 0xF7BE, PANEL = 0xFFFF, PANEL2 = 0xEF9F;
constexpr uint16_t CYAN = 0x067F, MINT = 0x05F3, GOLD = 0x8A5F, ROSE = 0xE91F;
constexpr uint16_t TEXT = 0x2128, MUTED = 0x7BCF, GREEN = 0x05A9, RED = 0xD8E4;
constexpr uint16_t VIOLET = 0x723F, BORDER = 0xD69F;
constexpr size_t MAX_ROLLS = 1024;

// ---------------- secret / sensitive state (fixed buffers only) ----------------
char rolls[MAX_ROLLS];
size_t rollCount = 0;
char entropyHex[65];                     // audit fingerprint (public)
char mnemonic[WC_MNEMONIC_MAX_LEN] = {0};
char address[WC_ADDRESS_MAX_LEN] = {0};
char quizBuf[12] = {0};
char tailBuf[25] = {0};
uint16_t wordOff[24] = {0};
uint8_t wordLen[24] = {0};
size_t quizLen = 0;
uint8_t quizPos[4] = {0};
uint8_t quizStep = 0;
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
// Quiz input waits for full key release before processing any event.
bool inputAwaitRelease = false;
// 10 visible 1-6 values derived from the first HWRNG block (report display)
char hwSample[24];
constexpr char FW_VERSION[] = "0.4.0";
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

// Per-key edge state for typed quiz input.
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
    if (why) *why = "DICE + HWRNG: 100 entries + SAR RNG. Dice fairness NOT required.";
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
  }
  // A 16 px status rail replaces the old 20 px framed banner.  It keeps the
  // safety state persistent without spending nearly a fifth of screen height.
  M5Cardputer.Display.fillRect(0, 0, 240, 16, PANEL);
  M5Cardputer.Display.drawFastHLine(0, 15, 240, BORDER);
  fillRound(6, 4, 8, 8, 4, radiosOffOK ? GREEN : RED);
  textAt(19, 4, radiosOffOK ? "DICE WALLET  /  OFFLINE" : "RADIO STATE ERROR", radiosOffOK ? TEXT : RED, PANEL);

  // Native M5Unified battery reading, kept inside the existing 16 px rail.
  // getBatteryLevel() returns a percentage, or a negative value when the
  // board cannot provide a reading.
  int battery = M5.Power.getBatteryLevel();
  char batteryText[5];
  if (battery < 0) {
    snprintf(batteryText, sizeof(batteryText), "--%%");
  } else {
    if (battery > 100) battery = 100;
    snprintf(batteryText, sizeof(batteryText), "%d%%", battery);
  }
  uint16_t batteryColor = battery >= 0 && battery <= 15 ? RED : GREEN;
  textAt(177, 4, batteryText, battery < 0 ? MUTED : TEXT, PANEL);
  M5Cardputer.Display.drawRoundRect(207, 3, 25, 10, 2, battery < 0 ? MUTED : TEXT);
  M5Cardputer.Display.fillRect(232, 6, 2, 4, battery < 0 ? MUTED : TEXT);
  M5Cardputer.Display.fillRect(210, 6, 19, 4, PANEL);
  if (battery >= 0) {
    int fill = (19 * battery + 99) / 100;
    if (fill) M5Cardputer.Display.fillRect(210, 6, fill, 4, batteryColor);
  }
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
  fillRound(7, 21, 226, 52, 7, PANEL); M5Cardputer.Display.drawRoundRect(7, 21, 226, 52, 7, BORDER);
  textAt(15, 27, "SELECT ENTROPY MODE", VIOLET, PANEL);
  textAt(15, 39, modeCursor == 0 ? "> 1) Von Neumann" : "  1) Von Neumann", modeCursor == 0 ? VIOLET : TEXT, PANEL);
  textAt(15, 50, modeCursor == 1 ? "> 2) Fair d6" : "  2) Fair d6", modeCursor == 1 ? VIOLET : TEXT, PANEL);
  textAt(15, 61, modeCursor == 2 ? "> 3) Dice + HWRNG" : "  3) Dice + HWRNG", modeCursor == 2 ? VIOLET : TEXT, PANEL);
  fillRound(7, 76, 226, 43, 6, PANEL2); M5Cardputer.Display.drawRoundRect(7, 76, 226, 43, 6, BORDER);
  if (modeCursor == 0) {
    textAt(15, 81, "Roll pairs; equal dropped.", TEXT, PANEL2);
    textAt(15, 93, "Handles fixed face bias.", TEXT, PANEL2);
    textAt(15, 105, "Rolls independent. ~615 typ.", TEXT, PANEL2);
  } else if (modeCursor == 1) {
    textAt(15, 81, "100 rolls, exact base-6.", ROSE, PANEL2);
    textAt(15, 93, "Bias NOT corrected.", ROSE, PANEL2);
    textAt(15, 105, "Fair d6 only. Not recommended.", ROSE, PANEL2);
  } else {
    textAt(15, 81, "100 dice/1-6 entries hashed,", TEXT, PANEL2);
    textAt(15, 93, "plus ESP32-S3 physical RNG.", TEXT, PANEL2);
    textAt(15, 105, "Dice bias harmless here.", MINT, PANEL2);
  }
  textAt(15, 122, ";=up .=down  Enter: select", MUTED, BG);
  String idLine = String(FW_VERSION) + " " + String(FW_GIT_SHA);
  textAt(168, 122, idLine, MUTED, BG);
}

void drawMain() {
  showingResult = false;
  drawHeader(drawnScreen != 1);
  drawnScreen = 1;
  computeStats();
  fillRound(7, 21, 118, 70, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 21, 118, 70, 8, BORDER);
  textAt(15, 28, "ROLLS", MUTED, PANEL); textAt(15, 41, String(rollCount), entropyReady() ? GREEN : VIOLET, PANEL, 2);
  textAt(68, 41, entropyMode == MODE_VN ? "VN " + String(vnBits) + "/256"
                        : (entropyMode == MODE_RAW ? "RAW " + String(rollCount) + "/100"
                                                   : "D+H " + String(rollCount) + "/100"),
         entropyReady() ? GREEN : GOLD, PANEL);
  textAt(15, 67, "ties " + String(ties) + "  streak " + String(maxStreak), MUTED, PANEL);
  textAt(15, 79, sdOK ? "SD report enabled" : "SD not mounted", sdOK ? GREEN : ROSE, PANEL);
  drawBars();
  fillRound(7, 96, 226, 34, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 96, 226, 34, 7, BORDER);
  rollTail(24);
  textAt(15, 104, tailBuf[0] ? tailBuf : "press one key: 1..6", TEXT, PANEL2);
  textAt(15, 118, statusLine, hasHash ? GREEN : MUTED, PANEL2);
}

void drawQuiz() {
  drawHeader(drawnScreen != 3);
  drawnScreen = 3;
  fillRound(7, 21, 226, 74, 8, PANEL); M5Cardputer.Display.drawRoundRect(7, 21, 226, 74, 8, BORDER);
  textAt(15, 29, "BACKUP CHECK " + String(quizStep + 1) + "/4", VIOLET, PANEL);
  textAt(15, 51, "Type word #" + String(quizPos[quizStep] + 1), TEXT, PANEL);
  textAt(15, 65, "then press Enter.", MUTED, PANEL);
  textAt(15, 81, quizBuf, CYAN, PANEL);
  fillRound(7, 99, 226, 31, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 99, 226, 31, 7, BORDER);
  textAt(15, 110, statusLine, MUTED, PANEL2);
  textAt(15, 121, "Enter=check  Del=" + String(quizLen ? "backspace" : "cancel"), TEXT, PANEL2);
}

void drawResult() {
  showingResult = true;
  // single solid panel shared by every page: incremental repaint is safe
  drawHeader(drawnScreen != 4);
  drawnScreen = 4;
  computeStats(); String why; bool ok = assessmentOK(&why);
  fillRound(7, 20, 226, 110, 9, PANEL); M5Cardputer.Display.drawRoundRect(7, 20, 226, 110, 9, ok ? VIOLET : RED);
  textAt(15, 26, "PAGE " + String(resultPage + 1) + "/" + String(PAGE_COUNT) + "   ;/.-navigate   esc-back", MUTED, PANEL);
  if (resultPage == PAGE_FINGERPRINT) {
    textAt(18, 48, "1) SHA256 FINGERPRINT", GREEN, PANEL);
    M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setTextColor(CYAN, PANEL);
    char fl[20];
    snprintf(fl, sizeof(fl), "1|%.16s", entropyHex); M5Cardputer.Display.drawString(fl, 12, 61);
    snprintf(fl, sizeof(fl), "2|%.16s", entropyHex + 16); M5Cardputer.Display.drawString(fl, 12, 77);
    snprintf(fl, sizeof(fl), "3|%.16s", entropyHex + 32); M5Cardputer.Display.drawString(fl, 12, 93);
    snprintf(fl, sizeof(fl), "4|%.16s", entropyHex + 48); M5Cardputer.Display.drawString(fl, 12, 109);
  } else if (resultPage >= PAGE_MNEMONIC_FIRST && resultPage < PAGE_MNEMONIC_FIRST + PAGE_MNEMONIC_COUNT) {
    uint8_t base = (resultPage - PAGE_MNEMONIC_FIRST) * 6;
    textAt(18, 38, "MNEMONIC " + String(base + 1) + "-" + String(base + 6) + " / 24", GREEN, PANEL);
    textAt(18, 46, "BIP39; Solana SLIP-0010 m/44'/501'", MUTED, PANEL);
    for (int k = 0; k < 6; ++k) {
      uint16_t i = base + k;
      if (i >= 24) break;
      char wordLine[48];
      snprintf(wordLine, sizeof(wordLine), "%u. %.*s", i + 1, (int)wordLen[i], mnemonic + wordOff[i]);
      textAt(18, 56 + k * 10, wordLine, TEXT, PANEL);
      wc_secure_zero(wordLine, sizeof(wordLine));
    }
    textAt(18, 116, backupVerified ? "Backup verified." : "Write words down. Enter=check", backupVerified ? GREEN : ROSE, PANEL);
  } else if (resultPage == PAGE_ADDRESS) {
    if (!backupVerified) {
      textAt(18, 46, "4) SOLANA ADDRESS", CYAN, PANEL);
      textAt(18, 62, "LOCKED - verify backup first.", ROSE, PANEL);
      textAt(18, 76, "Go to mnemonic pages,", TEXT, PANEL);
      textAt(18, 88, "press Enter, type 4 words.", TEXT, PANEL);
    } else {
      textAt(18, 46, "4) SOLANA ADDRESS", CYAN, PANEL);
      M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setTextColor(TEXT, PANEL);
      char al[22];
      snprintf(al, sizeof(al), "1|%.19s", address); M5Cardputer.Display.drawString(al, 12, 58);
      snprintf(al, sizeof(al), "2|%.19s", address + 19); M5Cardputer.Display.drawString(al, 12, 74);
      snprintf(al, sizeof(al), "3|%.6s", address + 38); M5Cardputer.Display.drawString(al, 12, 90);
      textAt(18, 108, "Path m/44'/501'/0'/0'", MUTED, PANEL);
      textAt(18, 118, "24 words -> Solflare import", MUTED, PANEL);
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
  f.println();
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
    f.println("hwrng_sample=" + String(hwSample[0] ? hwSample : "n/a") + " (display-only uniqueness check)");
    f.println("source_digests_saved=false");
  }
  f.println("max_streak=" + String(maxStreak));
  f.println("faces=" + String(faceCount[0]) + "," + String(faceCount[1]) + "," + String(faceCount[2]) + "," + String(faceCount[3]) + "," + String(faceCount[4]) + "," + String(faceCount[5]));
  f.println("audit_fingerprint_sha256=" + String(entropyHex));
  // address is gated on backup verification: never written to SD before the quiz passes
  f.println(backupVerified ? ("address=" + String(address[0] ? address : "n/a")) : "address=n/a (backup not verified)");
  f.println("bip39_passphrase=empty (not supported by firmware)");
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
  hwSample[0] = 0;  // fresh per build: report shows a sample only from this run
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
        statusLine = "dice transcript invalid";
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
      if (!wc_platform_hwrng_digest(hwD, hwSample)) {
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

  wc_mnemonic_from_entropy(bytes, mnemonic);
  parseMnemonicWords();
  uint8_t seed[64];
  // This appliance deliberately implements the interoperable 24-word wallet
  // only. BIP39's optional passphrase is always the empty string.
  wc_seed_from_mnemonic(mnemonic, "", seed);
  wc_solana_address(seed, address);
  wipeBytes(seed, 64);
  wipeBytes(bytes, 32);
  wipeBytes(hash, 32);

  backupVerified = false;
  quizActive = false;
  quizStep = 0;
  quizLen = 0;
  memset(quizBuf, 0, sizeof(quizBuf));
  waitingRelease = true;
  hasHash = true; statusLine = "backup: verify words (Enter)"; resultPage = PAGE_FINGERPRINT; lastAssessment = why;
  writeReport(true, why); drawResult();
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
    else statusLine = "mode: Dice + HWRNG (100 entries + SAR RNG)";
    drawMain();
    return;
  }
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
  wipeChars(hwSample, sizeof(hwSample));
  wipeChars(mnemonic, sizeof(mnemonic));
  wipeChars(address, sizeof(address));
  memset(quizBuf, 0, sizeof(quizBuf));
  quizLen = 0;
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
  if (quizActive) {
    if (inputAwaitRelease) return;  // ignore the keypress that opened this mode
    handleQuiz(ks);
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
      buildWallet();
    } else {
      buildWallet();
    }
    return;
  }

  if (!showingResult && diceCount == 1) acceptRoll(dice);
  else if (!showingResult && diceCount > 1) { statusLine = "ignored chord; press one key"; drawMain(); }
}
