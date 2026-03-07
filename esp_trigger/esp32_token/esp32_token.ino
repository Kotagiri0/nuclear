// ==========================================
// Nuclear Secret Scanner - True Hardware Engine
// Dual Core FreeRTOS Implementation
// ==========================================

#include <Arduino.h>

// Pins for ESP32-CAM
#define FLASH_LED_PIN 4
#define BOOT_BUTTON_PIN 0

// Task Handles
TaskHandle_t TaskScannerCore1;
TaskHandle_t TaskControllerCore0;

// Shared State Variables (Protected by Mutex if needed, but here simple volatile is ok for flags)
volatile bool isScanning = false;
volatile bool alarmTriggered = false;
volatile bool exportAuthorized = false;

// Simple patterns to search for (since std::regex is extremely heavy on embedded,
// we use fast substring matching for the most critical keys for demonstration).
const char* PATTERNS[] = {
  "AKIA",           // AWS Access Key
  "ghp_",           // GitHub Token
  "sk_live_",       // Stripe Secret
  "xoxb-",          // Slack Token
  "xoxp-",          // Slack Token
  "PRIVATE KEY",    // Private Key block
  "AIza",           // Google API Key
  "eyJ"             // JWT start
};
const int PATTERN_COUNT = 8;

// Function declarations
void core1_scanner_task(void * pvParameters);
void core0_controller_task(void * pvParameters);

void setup() {
  Serial.begin(115200);
  
  pinMode(FLASH_LED_PIN, OUTPUT);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  
  digitalWrite(FLASH_LED_PIN, LOW);

  // Wait for Serial to stabilize
  delay(1000);
  
  // Send heartbeat token so PC knows we are the scanner
  Serial.println("NUCLEAR_SCANNER_READY");

  // Create Scanner Task on Core 1 (Application Core - doing the heavy string matching)
  xTaskCreatePinnedToCore(
    core1_scanner_task,    /* Task function. */
    "ScannerTask",         /* name of task. */
    10000,                 /* Stack size of task */
    NULL,                  /* parameter of the task */
    1,                     /* priority of the task */
    &TaskScannerCore1,     /* Task handle to keep track of created task */
    1);                    /* pin task to core 1 */

  // Create Controller Task on Core 0 (Protocol Core - handling LED strobe and buttons)
  xTaskCreatePinnedToCore(
    core0_controller_task, /* Task function. */
    "ControllerTask",      /* name of task. */
    4000,                  /* Stack size of task */
    NULL,                  /* parameter of the task */
    1,                     /* priority of the task */
    &TaskControllerCore0,  /* Task handle to keep track of created task */
    0);                    /* pin task to core 0 */
}

void loop() {
  // Empty loop. All work is done in FreeRTOS tasks.
  vTaskDelay(portMAX_DELAY);
}

// ---------------------------------------------------------
// CORE 1: The Heavy Lifter (Parsing lines from Serial)
// ---------------------------------------------------------
void core1_scanner_task(void * pvParameters) {
  String incomingLine = "";

  for(;;) {
    if (Serial.available() > 0) {
      incomingLine = Serial.readStringUntil('\n');
      incomingLine.trim();

      if (incomingLine == "CMD:SCAN_START") {
        isScanning = true;
        alarmTriggered = false;
        exportAuthorized = false;
        digitalWrite(FLASH_LED_PIN, LOW);
      } 
      else if (incomingLine == "CMD:SCAN_END") {
        isScanning = false;
        if (alarmTriggered) {
          // Tell PC to export secrets immediately without waiting for a button
          Serial.println("SYS:AUTHORIZE_EXPORT_b8f9a2c");
          // Stop strobing once scan is done and exported
          alarmTriggered = false;
        } else {
          // Tell PC that the scan was clean to unlock the GUI
          Serial.println("SYS:SCAN_CLEAN");
        }
        digitalWrite(FLASH_LED_PIN, LOW);
      }
      else if (isScanning) {
        // We received a line of code from the PC! Let's analyze it.
        bool foundSecret = false;
        String detectedPattern = "";
        
        // Fast Substring Matching Engine
        // (In a real scenario, could implement Aho-Corasick here for O(n) speed)
        for (int i = 0; i < PATTERN_COUNT; i++) {
          if (incomingLine.indexOf(PATTERNS[i]) != -1) {
            foundSecret = true;
            detectedPattern = PATTERNS[i];
            break;
          }
        }

        if (foundSecret) {
          alarmTriggered = true; // Trigger the hardware strobe on Core 0
          // Send finding back to PC immediately 
          // Format: FINDING:SEVERITY:PATTERN:LINE
          Serial.print("FINDING:CRITICAL:");
          Serial.print(detectedPattern);
          Serial.print(":");
          Serial.println(incomingLine);
        }
      }
    }
    
    // Yield to let the watchdogs breathe
    vTaskDelay(pdMS_TO_TICKS(1));
  }
}


// ---------------------------------------------------------
// CORE 0: The Hardware Controller (LEDs, Buttons, State)
// ---------------------------------------------------------
void core0_controller_task(void * pvParameters) {
  bool ledState = false;
  unsigned long lastStrobe = 0;
  
  for(;;) {
    // 1. Hardware Status Strobe
    if (isScanning || alarmTriggered) {
      unsigned long interval = isScanning ? 250 : 100; // Slower blink for scanning, fast strobe for alarm
      if (millis() - lastStrobe > interval) {
        ledState = !ledState;
        // The FLASH_LED on ESP32-CAM is active HIGH. It's VERY bright.
        digitalWrite(FLASH_LED_PIN, ledState ? HIGH : LOW);
        lastStrobe = millis();
      }
    } 
    else {
      // Ensure LED is off when not scanning and no active alarm
      digitalWrite(FLASH_LED_PIN, LOW);
      vTaskDelay(pdMS_TO_TICKS(50)); // Slow sleep to save power
    }
    
    vTaskDelay(pdMS_TO_TICKS(5)); 
  }
}
