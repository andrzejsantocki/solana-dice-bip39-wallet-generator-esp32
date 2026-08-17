#include <M5Cardputer.h>
#include <SPI.h>
#include <SD.h>
#include <mbedtls/sha256.h>

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

String rolls, entropyHex, reportText;
String statusLine = "VN mode: enter d6 rolls 1..6";
uint16_t faceCount[6] = {0};
uint16_t vnBits = 0, ties = 0, maxStreak = 0;
uint32_t lastRollMs = 0;
uint32_t lastNavMs = 0;
uint32_t lastEnterMs = 0;
char lastRollChar = 0;
int resultPage = 0;
bool hasHash = false, showingResult = false, sdOK = false;

void fillRound(int x, int y, int w, int h, int r, uint16_t color) { M5Cardputer.Display.fillRoundRect(x, y, w, h, r, color); }
void textAt(int x, int y, const String& s, uint16_t fg = TEXT, uint16_t bg = BG, float size = 1) {
  M5Cardputer.Display.setTextSize(size); M5Cardputer.Display.setTextColor(fg, bg); M5Cardputer.Display.drawString(s, x, y);
}
void label(int x, int y, const String& s) { textAt(x, y, s, MUTED, BG); }

void computeStats() {
  memset(faceCount, 0, sizeof(faceCount)); vnBits = 0; ties = 0; maxStreak = 0;
  char prev = 0; uint16_t streak = 0;
  for (size_t i = 0; i < rolls.length(); ++i) {
    char c = rolls[i]; if (c >= '1' && c <= '6') faceCount[c - '1']++;
    if (c == prev) streak++; else { prev = c; streak = 1; }
    if (streak > maxStreak) maxStreak = streak;
  }
  for (size_t i = 1; i < rolls.length(); i += 2) {
    char a = rolls[i - 1], b = rolls[i];
    if (a == b) ties++; else vnBits++;
  }
}

bool assessmentOK(String* why = nullptr) {
  computeStats();
  String w = "";
  if (rolls.length() < 620) w += "Need ~620+ rolls for VN 256 bits. ";
  if (vnBits < 256) w += "VN bits <256. ";
  for (int i = 0; i < 6; ++i) if (faceCount[i] == 0) w += "Missing face " + String(i + 1) + ". ";
  if (maxStreak >= 8) w += "Long streak. ";
  float pairs = rolls.length() / 2.0f;
  float tieRate = pairs > 0 ? ties / pairs : 0;
  if (pairs >= 100 && (tieRate < 0.08f || tieRate > 0.27f)) w += "Tie rate off. ";
  if (why) *why = w.length() ? w : "PASS: no simple anomaly detected. VN>=256.";
  return w.length() == 0;
}

void drawHeader() {
  M5Cardputer.Display.fillRect(0, 0, 240, 135, BG);
  for (int i = 0; i < 240; i += 8) M5Cardputer.Display.drawFastVLine(i, 0, 135, (i % 24 == 0) ? 0x0AEE : 0x09AD);
  fillRound(4, 3, 232, 20, 6, PANEL2); M5Cardputer.Display.drawRoundRect(4, 3, 232, 20, 6, CYAN);
  textAt(12, 8, "DICE WALLET // VN ENFORCED", CYAN, PANEL2);
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
  textAt(15, 37, "rolls", MUTED, PANEL); textAt(15, 50, String(rolls.length()), rolls.length() >= 620 ? GREEN : GOLD, PANEL, 2);
  textAt(68, 50, "VN " + String(vnBits) + "/256", vnBits >= 256 ? GREEN : GOLD, PANEL);
  textAt(15, 75, "ties " + String(ties) + "  streak " + String(maxStreak), MUTED, PANEL);
  textAt(15, 86, sdOK ? "SD report enabled" : "SD not mounted", sdOK ? MINT : ROSE, PANEL);
  drawBars();
  fillRound(7, 103, 226, 27, 7, PANEL2); M5Cardputer.Display.drawRoundRect(7, 103, 226, 27, 7, 0x3338);
  String tail = rolls.length() > 24 ? rolls.substring(rolls.length() - 24) : rolls;
  textAt(15, 110, tail.length() ? tail : "1..6 roll  enter=validate/hash", TEXT, PANEL2);
  textAt(15, 121, statusLine, hasHash ? GREEN : MUTED, PANEL2);
}

void drawResult() {
  showingResult = true;
  drawHeader(); computeStats(); String why; bool ok = assessmentOK(&why);
  fillRound(8, 28, 224, 98, 10, PANEL); M5Cardputer.Display.drawRoundRect(8, 28, 224, 98, 10, ok ? GREEN : RED);
  textAt(18, 36, "page " + String(resultPage + 1) + "/6  arrows up/down", MUTED, PANEL);
  if (resultPage == 0) {
    textAt(18, 48, "1) SHA256 ENTROPY", GREEN, PANEL);
    M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setTextColor(CYAN, PANEL);
    M5Cardputer.Display.drawString("1|" + entropyHex.substring(0, 16), 12, 61);
    M5Cardputer.Display.drawString("2|" + entropyHex.substring(16, 32), 12, 77);
    M5Cardputer.Display.drawString("3|" + entropyHex.substring(32, 48), 12, 93);
    M5Cardputer.Display.drawString("4|" + entropyHex.substring(48, 64), 12, 109);
  } else if (resultPage == 1) {
    textAt(18, 50, "2) PASSPHRASE", GOLD, PANEL);
    textAt(18, 64, "Optional 25th word layer.", TEXT, PANEL);
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
    textAt(18, 50, ok ? "5) ASSESSMENT: PASS" : "5) ASSESSMENT: FAIL", ok ? GREEN : RED, PANEL);
    textAt(18, 64, why.substring(0, 34), ok ? GREEN : ROSE, PANEL);
    textAt(18, 76, why.substring(34, 68), ok ? GREEN : ROSE, PANEL);
    textAt(18, 100, "Fail => do not use/fund.", ROSE, PANEL);
  } else {
    textAt(18, 50, "6) SD / AUDIT", sdOK ? MINT : ROSE, PANEL);
    textAt(18, 64, sdOK ? "/dice_wallet/report.txt" : "SD unavailable", TEXT, PANEL);
    textAt(18, 82, "Report excludes rolls.", ROSE, PANEL);
    textAt(18, 104, "Del clears. Digits return.", MUTED, PANEL);
  }
}

void writeReport(bool ok, const String& why) {
  if (!sdOK) return;
  SD.mkdir("/dice_wallet");
  File f = SD.open("/dice_wallet/report.txt", FILE_APPEND);
  if (!f) return;
  f.println("--- dice wallet assessment ---");
  f.println(ok ? "PASS" : "FAIL");
  f.println(why);
  f.println("rolls=" + String(rolls.length()));
  f.println("vn_bits=" + String(vnBits));
  f.println("ties=" + String(ties));
  f.println("max_streak=" + String(maxStreak));
  f.println("faces=" + String(faceCount[0]) + "," + String(faceCount[1]) + "," + String(faceCount[2]) + "," + String(faceCount[3]) + "," + String(faceCount[4]) + "," + String(faceCount[5]));
  f.println("entropy_sha256_vn=" + entropyHex);
  f.println("roll_transcript_saved=false");
  f.close();
}

void makeEntropy() {
  String why; bool ok = assessmentOK(&why);
  if (!ok) { hasHash = false; statusLine = "validation failed"; entropyHex = ""; resultPage = 4; writeReport(false, why); drawResult(); return; }

  uint8_t bytes[32] = {0}; uint16_t bit = 0;
  for (size_t i = 1; i < rolls.length() && bit < 256; i += 2) {
    char a = rolls[i - 1], b = rolls[i]; if (a == b) continue;
    if (a > b) bytes[bit / 8] |= (1 << (7 - (bit % 8)));
    bit++;
  }
  uint8_t hash[32]; mbedtls_sha256(bytes, 32, hash, 0);
  entropyHex = ""; const char* hx = "0123456789abcdef";
  for (uint8_t b : hash) { entropyHex += hx[b >> 4]; entropyHex += hx[b & 15]; }
  hasHash = true; statusLine = "VN entropy hash ready"; resultPage = 0; writeReport(true, why); drawResult();
}

void handleChar(char c) {
  if (c < '1' || c > '6') return;

  uint32_t now = millis();
  if (c == lastRollChar && now - lastRollMs < 350) {
    statusLine = "ignored held key repeat";
    drawMain();
    return;
  }

  lastRollChar = c;
  lastRollMs = now;
  rolls += c;
  hasHash = false;
  statusLine = "roll accepted";
  drawMain();
}

void initSD() {
  SPI.begin(SD_SPI_SCK_PIN, SD_SPI_MISO_PIN, SD_SPI_MOSI_PIN, SD_SPI_CS_PIN);
  sdOK = SD.begin(SD_SPI_CS_PIN, SPI, 25000000) && SD.cardType() != CARD_NONE;
}
}  // namespace

void setup() {
  auto cfg = M5.config(); M5Cardputer.begin(cfg, true); M5Cardputer.Display.setRotation(1); M5Cardputer.Display.setFont(&fonts::Font0);
  initSD(); drawMain();
}

void loop() {
  M5Cardputer.update();
  if (!M5Cardputer.Keyboard.isPressed()) return;

  Keyboard_Class::KeysState ks = M5Cardputer.Keyboard.keysState();
  bool prev = false, next = false;
  for (auto h : ks.hid_keys) {
    if (h == HID_UP || h == HID_LEFT) prev = true;
    if (h == HID_DOWN || h == HID_RIGHT) next = true;
  }
  for (auto c : ks.word) {
    if (c == 'w' || c == 'a' || c == 'W' || c == 'A') prev = true;
    if (c == 's' || c == 'd' || c == 'S' || c == 'D') next = true;
  }

  uint32_t now = millis();
  if (showingResult && (prev || next) && now - lastNavMs > 180) {
    resultPage = prev ? (resultPage + 5) % 6 : (resultPage + 1) % 6;
    lastNavMs = now;
    drawResult();
    return;
  }

  for (auto c : ks.word) handleChar(c);
  if (ks.del) {
    if (showingResult || hasHash) { rolls = ""; entropyHex = ""; hasHash = false; showingResult = false; statusLine = "cleared"; resultPage = 0; lastRollChar = 0; lastRollMs = 0; }
    else if (rolls.length()) { rolls.remove(rolls.length() - 1); statusLine = "last roll erased"; }
    drawMain();
  }
  if (ks.enter && now - lastEnterMs > 500) {
    lastEnterMs = now;
    makeEntropy();
  }
}
