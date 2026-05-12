// ============================================================
// CPE 301 Final Project - Tamper Detection Security System
// NAME: Arwen Antes
// ============================================================

#include <LiquidCrystal.h>
#include <Wire.h>
#include <RTClib.h>
#include <Keypad.h>
#define RDA 0x80
#define TBE 0x20

volatile unsigned char *myUCSR0A = (unsigned char *)0x00C0;
volatile unsigned char *myUCSR0B = (unsigned char *)0x00C1;
volatile unsigned char *myUCSR0C = (unsigned char *)0x00C2;
volatile unsigned int  *myUBRR0 = (unsigned int *) 0x00C4;
volatile unsigned char *myUDR0 = (unsigned char *)0x00C6;
volatile unsigned char *portDDRA = (unsigned char *) 0x21;
volatile unsigned char *portA = (unsigned char *) 0x22;
volatile unsigned char *pinA = (unsigned char *) 0x20;

volatile unsigned char *portDDRC = (unsigned char *) 0x34;
volatile unsigned char *portC = (unsigned char *) 0x35;
volatile unsigned char *pinC = (unsigned char *) 0x33;

volatile unsigned char *portDDRE = (unsigned char *) 0x2D;
volatile unsigned char *portE = (unsigned char *) 0x2E;
volatile unsigned char *pinE = (unsigned char *) 0x2C;

volatile unsigned char *portDDRD = (unsigned char *) 0x2A;
volatile unsigned char *portD = (unsigned char *) 0x2B;
volatile unsigned char *pinD = (unsigned char *) 0x29;

volatile unsigned char *myADMUX = (unsigned char *) 0x7C;
volatile unsigned char *myADCSRB = (unsigned char *) 0x7B;
volatile unsigned char *myADCSRA = (unsigned char *) 0x7A;
volatile unsigned int  *myADCDATA = (unsigned int *)  0x78;

volatile unsigned char *myTCCR1A = (unsigned char *) 0x80;
volatile unsigned char *myTCCR1B = (unsigned char *) 0x81;
volatile unsigned char *myTCCR1C = (unsigned char *) 0x82;
volatile unsigned char *myTIMSK1 = (unsigned char *) 0x6F;
volatile unsigned int  *myTCNT1  = (unsigned int *)  0x84;
volatile unsigned char *myTIFR1  = (unsigned char *) 0x36;

const int RS = 12, EN = 11, D4 = 5, D5 = 4, D6 = 3, D7 = 2;
LiquidCrystal lcd(RS, EN, D4, D5, D6, D7);

RTC_DS1307 rtc;

const int ROW_NUM = 4;
const int COLUMN_NUM = 4;
char keys[ROW_NUM][COLUMN_NUM] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte pin_rows[ROW_NUM] = {38, 40, 42, 44};
byte pin_column[COLUMN_NUM] = {46, 48, 50, 52};
Keypad keypad = Keypad(makeKeymap(keys), pin_rows, pin_column, ROW_NUM, COLUMN_NUM);

#define MPU_ADDR  0x69 
#define MPU_PWR_MGMT_1  0x6B  
#define MPU_ACCEL_XOUT_H  0x3B 

int16_t baseAccelX = 0;
int16_t baseAccelY = 0;
int16_t baseAccelZ = 0;

const int16_t ACCEL_THRESHOLD = 5000;
bool mpuError = false;

enum SystemState {
  STATE_OFF,
  STATE_IDLE,
  STATE_ACTIVE,
  STATE_ERROR
};

volatile SystemState currentState = STATE_OFF;
volatile bool onButtonPressed = false;

unsigned long lastDisplayTime = 0;
const unsigned long DISPLAY_INTERVAL = 60000; 

unsigned long idleEntryTime = 0;
const unsigned long GRACE_PERIOD = 5000; 

int baselineLightLevel = 0;
const int LIGHT_THRESHOLD = 80;
const int ADC_ERROR_LOW = 5;
const int ADC_ERROR_HIGH = 1018;

const char CORRECT_PIN[] = "1234";
char enteredPIN[5];
int pinIndex = 0;
int failedAttempts = 0;
const int MAX_ATTEMPTS = 3;

void U0Init(unsigned long U0baud) {
  unsigned long FCPU = 16000000;
  unsigned int tbaud;
  tbaud = (FCPU / 16 / U0baud - 1);
  *myUCSR0A = 0x20;
  *myUCSR0B = 0x18;
  *myUCSR0C = 0x06;
  *myUBRR0  = tbaud;
}

unsigned char U0kbhit() {
  return (*myUCSR0A & RDA);
}

unsigned char U0getchar() {
  return *myUDR0;
}

void U0putchar(unsigned char U0pdata) {
  while (!(*myUCSR0A & TBE));
  *myUDR0 = U0pdata;
}

void U0print(const char* str) {
  while (*str) {
    U0putchar(*str++);
  }
}

void U0println(const char* str) {
  U0print(str);
  U0putchar('\r');
  U0putchar('\n');
}

void U0printInt(int val) {
  char buf[12];
  itoa(val, buf, 10);
  U0print(buf);
}

void adc_init() {
  *myADCSRA |= 0b10000000; 
  *myADCSRA &= 0b11011111;
  *myADCSRA &= 0b11110111;
  *myADCSRA |= 0b00000111; 

  *myADCSRB &= 0b11110111; 
  *myADCSRB &= 0b11111000; 

  *myADMUX &= 0b01111111; 
  *myADMUX |= 0b01000000; 
  *myADMUX &= 0b11011111; 
  *myADMUX &= 0b11100000;
}

unsigned int adc_read(unsigned char channel) {
  *myADMUX &= 0b11100000;
  *myADCSRB &= 0b11110111;

  if (channel > 7) {
    channel -= 8;
    *myADCSRB |= 0b00001000;
  }
  *myADMUX |= (channel & 0x07);
  *myADCSRA |= 0b01000000;
  while (*myADCSRA & 0b01000000);
  return *myADCDATA;
}

void portA_set_output(uint8_t bit) {
  *portDDRA |= (0x01 << bit);
}
void portA_set_input_pullup(uint8_t bit) {
  *portDDRA &= ~(0x01 << bit);
  *portA |= (0x01 << bit);
}
void portA_write_high(uint8_t bit) {
  *portA |= (0x01 << bit);
}
void portA_write_low(uint8_t bit) {
  *portA &= ~(0x01 << bit);
}
uint8_t portA_read(uint8_t bit) {
  return (*pinA >> bit) & 0x01;
}
uint8_t portC_read(uint8_t bit) {
  return (*pinC >> bit) & 0x01;
}

void led1_on() { portA_write_high(0); }
void led1_off() { portA_write_low(0);  }
void led2_on() { portA_write_high(1); }
void led2_off() { portA_write_low(1);  }
void led3_on() { portA_write_high(2); }
void led3_off() { portA_write_low(2);  }
void led4_on() { portA_write_high(3); }
void led4_off() { portA_write_low(3);  }

void buzzer_on() { portA_write_high(4); }
void buzzer_off() { portA_write_low(4);  }

void all_leds_off() {
  led1_off();
  led2_off();
  led3_off();
  led4_off();
}

void mpu_init() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(MPU_PWR_MGMT_1); 
  Wire.write(0x00);   
  uint8_t error = Wire.endTransmission();

  if (error != 0) {
    mpuError = true;
    U0println("ERROR: MPU-9250 not found on I2C bus!");
  } else {
    mpuError = false;
    U0println("MPU-9250 initialized at address 0x69");
  }
}

// Read raw accelerometer values (X, Y, Z)
bool mpu_read_accel(int16_t* ax, int16_t* ay, int16_t* az) {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(MPU_ACCEL_XOUT_H);
  uint8_t error = Wire.endTransmission(false);

  if (error != 0) {
    return false;
  }

  Wire.requestFrom((uint8_t)MPU_ADDR, (uint8_t)6);
  if (Wire.available() < 6) {
    return false;
  }
  *ax = (Wire.read() << 8) | Wire.read();
  *ay = (Wire.read() << 8) | Wire.read();
  *az = (Wire.read() << 8) | Wire.read();

  return true;
}

void mpu_capture_baseline() {
  if (mpuError) return;

  int16_t ax, ay, az;
  if (mpu_read_accel(&ax, &ay, &az)) {
    baseAccelX = ax;
    baseAccelY = ay;
    baseAccelZ = az;

    char msg[60];
    sprintf(msg, "Accel baseline X:%d Y:%d Z:%d", baseAccelX, baseAccelY, baseAccelZ);
    log_event(msg);
  } else {
    mpuError = true;
    U0println("ERROR: Failed to read MPU-9250 baseline");
  }
}

bool check_accel_tamper(int16_t* ax, int16_t* ay, int16_t* az) {
  if (mpuError) return false;

  if (!mpu_read_accel(ax, ay, az)) {
    mpuError = true;
    return false;
  }

  int16_t diffX = *ax - baseAccelX;
  int16_t diffY = *ay - baseAccelY;
  int16_t diffZ = *az - baseAccelZ;

  if (diffX < 0) diffX = -diffX;
  if (diffY < 0) diffY = -diffY;
  if (diffZ < 0) diffZ = -diffZ;

  return (diffX > ACCEL_THRESHOLD || diffY > ACCEL_THRESHOLD || diffZ > ACCEL_THRESHOLD);
}

void log_event(const char* message) {
  DateTime now = rtc.now();
  char timestamp[25];
  sprintf(timestamp, "[%04d-%02d-%02d %02d:%02d:%02d] ", now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());
  U0print(timestamp);
  U0println(message);
}

void onButtonISR() {
  if (currentState == STATE_OFF) {
    onButtonPressed = true;
  }
}

void led_test() {
  unsigned long start;

  led1_on();
  start = millis();
  while (millis() - start < 300);
  led1_off();

  led2_on();
  start = millis();
  while (millis() - start < 300);
  led2_off();

  led3_on();
  start = millis();
  while (millis() - start < 300);
  led3_off();

  led4_on();
  start = millis();
  while (millis() - start < 300);
  led4_off();
}

void enter_off_state() {
  currentState = STATE_OFF;
  all_leds_off();
  buzzer_off();
  led1_on();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("SYSTEM OFF");
  lcd.setCursor(0, 1);
  lcd.print("Press ON to arm");

  log_event("STATE -> OFF");

  pinIndex = 0;
  failedAttempts = 0;
}

void enter_idle_state() {
  currentState = STATE_IDLE;
  all_leds_off();
  buzzer_off();

  led_test();
  baselineLightLevel = adc_read(0);
  mpu_capture_baseline();

  led2_on();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("IDLE: Arming...");

  log_event("STATE -> IDLE (armed)");

  char baseMsg[40];
  sprintf(baseMsg, "Baseline light: %d", baselineLightLevel);
  log_event(baseMsg);

  pinIndex = 0;
  failedAttempts = 0;
  lastDisplayTime = millis();
  idleEntryTime = millis();
  log_event("Grace period: 5 seconds to step away");
}

void enter_active_state(const char* trigger) {
  currentState = STATE_ACTIVE;
  all_leds_off();
  led3_on();
  buzzer_on();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("!! TAMPER !!");
  lcd.setCursor(0, 1);
  lcd.print(trigger);

  char logMsg[50];
  sprintf(logMsg, "STATE -> ACTIVE (%s)", trigger);
  log_event(logMsg);

  pinIndex = 0;
  failedAttempts = 0;
  lastDisplayTime = millis();
}

void enter_error_state(const char* reason) {
  currentState = STATE_ERROR;
  all_leds_off();
  buzzer_off();
  led4_on();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ERROR:");
  lcd.setCursor(0, 1);
  lcd.print(reason);

  char logMsg[50];
  sprintf(logMsg, "STATE -> ERROR (%s)", reason);
  log_event(logMsg);
}

bool check_light_sensor(int* lightVal) {
  *lightVal = adc_read(0);
  int diff = *lightVal - baselineLightLevel;
  if (diff < 0) diff = -diff;
  return (diff > LIGHT_THRESHOLD);
}

bool is_sensor_error(int val) {
  return (val < ADC_ERROR_LOW || val > ADC_ERROR_HIGH);
}

bool off_button_pressed() {
  return (portA_read(5) == 0);
}

bool reset_button_pressed() {
  return (portA_read(6) == 0);
}

void handle_keypad() {
  char key = keypad.getKey();
  if (key) {
    if (key == '#') {
      // '#' = submit PIN
      enteredPIN[pinIndex] = '\0';

      if (strcmp(enteredPIN, CORRECT_PIN) == 0) {
        log_event("PIN accepted - disarming");
        enter_idle_state();
      } else {
        failedAttempts++;
        char msg[40];
        sprintf(msg, "Wrong PIN (attempt %d/%d)", failedAttempts, MAX_ATTEMPTS);
        log_event(msg);

        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("WRONG PIN!");
        lcd.setCursor(0, 1);

        if (failedAttempts >= MAX_ATTEMPTS) {
          lcd.print("LOCKED OUT");
          log_event("Keypad locked out");
        } else {
          char attStr[16];
          sprintf(attStr, "Tries: %d/%d", failedAttempts, MAX_ATTEMPTS);
          lcd.print(attStr);
        }
      }
      pinIndex = 0;

    } else if (key == '*') {
      // '*' = clear entry
      pinIndex = 0;
      lcd.setCursor(0, 1);
      lcd.print("PIN cleared     ");

    } else if (pinIndex < 4) {
      enteredPIN[pinIndex++] = key;
      lcd.setCursor(0, 1);
      lcd.print("PIN: ");
      for (int i = 0; i < pinIndex; i++) {
        lcd.print('*');
      }
      lcd.print("    ");
    }
  }
}

void display_sensor_data() {
  int lightVal = adc_read(0);

  int16_t ax = 0, ay = 0, az = 0;
  bool accelOk = true;
  if (!mpuError) {
    accelOk = mpu_read_accel(&ax, &ay, &az);
  }

  lcd.clear();
  lcd.setCursor(0, 0);
  char line1[17];
  sprintf(line1, "Light: %d", lightVal);
  lcd.print(line1);
  lcd.setCursor(0, 1);
  if (accelOk && !mpuError) {
    char line2[17];
    sprintf(line2, "X:%d Y:%d", ax / 100, ay / 100);
    lcd.print(line2);
  } else {
    lcd.print("Accel: ERR");
  }

  char logLine[80];
  sprintf(logLine, "Sensors - Light:%d (base:%d) AccX:%d AccY:%d AccZ:%d",
          lightVal, baselineLightLevel, ax, ay, az);
  log_event(logLine);
}

void setup() {
  U0Init(9600);
  adc_init();

  portA_set_output(0);  // LED1 - Pin 22
  portA_set_output(1);  // LED2 - Pin 23
  portA_set_output(2);  // LED3 - Pin 24
  portA_set_output(3);  // LED4 - Pin 25
  portA_set_output(4);  // Buzzer - Pin 26

  portA_set_input_pullup(5);  // OFF button - Pin 27
  portA_set_input_pullup(6);  // RESET button - Pin 28

  // ON button on Pin 18 (INT3)
  *portDDRD &= ~(0x01 << 3);  // Set PD3 as input
  *portD |= (0x01 << 3);  // Enable pull-up on PD3
  attachInterrupt(digitalPinToInterrupt(18), onButtonISR, FALLING);

  lcd.begin(16, 2);
  Wire.begin();
  rtc.begin();
  mpu_init();

  U0println("=== Tamper Detection System ===");
  U0println("System initialized.");
  U0println("MPU-9250: AD0 -> HIGH for address 0x69");
  U0println("DS1307 RTC: address 0x68");
  enter_off_state();
}

void loop() {
  // STATE: OFF
  if (currentState == STATE_OFF) {
    if (onButtonPressed) {
      onButtonPressed = false;
      enter_idle_state();
    }
  }
  // STATE: IDLE (monitoring)
  else if (currentState == STATE_IDLE) {
    if (off_button_pressed()) {
      enter_off_state();
      unsigned long db = millis();
      while (millis() - db < 200); // debounce
      return;
    }

    // During grace period, don't check sensors
    // This lets the user step away after arming
    if (millis() - idleEntryTime < GRACE_PERIOD) {
      unsigned long remaining = (GRACE_PERIOD - (millis() - idleEntryTime)) / 1000;
      lcd.setCursor(0, 1);
      char countMsg[17];
      sprintf(countMsg, "Arming in %lus... ", remaining + 1);
      lcd.print(countMsg);
      return;
    }

    // After grace period, update LCD to show monitoring
    static bool graceJustEnded = false;
    if (!graceJustEnded || (millis() - idleEntryTime >= GRACE_PERIOD && millis() - idleEntryTime < GRACE_PERIOD + 100)) {
      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("IDLE: Monitoring");
      lcd.setCursor(0, 1);
      lcd.print("System armed");
      log_event("Grace period over - monitoring active");

      // Recapture baselines now that user has stepped away
      baselineLightLevel = adc_read(0);
      mpu_capture_baseline();

      char baseMsg[40];
      sprintf(baseMsg, "New baseline light: %d", baselineLightLevel);
      log_event(baseMsg);

      graceJustEnded = true;
    }

    // Read light sensor
    int lightVal = 0;
    bool lightTamper = check_light_sensor(&lightVal);

    // Read accelerometer for physical disturbance
    int16_t ax = 0, ay = 0, az = 0;
    bool accelTamper = check_accel_tamper(&ax, &ay, &az);

    // Sensor error checks
    if (is_sensor_error(lightVal)) {
      graceJustEnded = false;
      enter_error_state("Light sensor");
      return;
    }
    if (mpuError) {
      graceJustEnded = false;
      enter_error_state("Accelerometer");
      return;
    }

    // Tamper event checks
    if (lightTamper) {
      graceJustEnded = false;
      enter_active_state("Light change");
      return;
    }
    if (accelTamper) {
      graceJustEnded = false;
      enter_active_state("Phys disturb");
      return;
    }

    // Display sensor data every 1 minute
    if (millis() - lastDisplayTime >= DISPLAY_INTERVAL) {
      lastDisplayTime = millis();
      display_sensor_data();
    }
  }

  // STATE: ACTIVE (alarm triggered)
  else if (currentState == STATE_ACTIVE) {
    // Check OFF button
    if (off_button_pressed()) {
      enter_off_state();
      unsigned long db = millis();
      while (millis() - db < 200);
      return;
    }

    // Sensor error check
    int lightVal = adc_read(0);
    if (is_sensor_error(lightVal)) {
      enter_error_state("Sensor fault");
      return;
    }

    // Keypad PIN input (unless locked out)
    if (failedAttempts < MAX_ATTEMPTS) {
      handle_keypad();
    }

    // Log every 1 minute
    if (millis() - lastDisplayTime >= DISPLAY_INTERVAL) {
      lastDisplayTime = millis();
      int16_t ax = 0, ay = 0, az = 0;
      if (!mpuError) {
        mpu_read_accel(&ax, &ay, &az);
      }
      char logLine[80];
      sprintf(logLine, "ACTIVE - Light:%d AccX:%d AccY:%d AccZ:%d",
              lightVal, ax, ay, az);
      log_event(logLine);
    }
  }

  // STATE: ERROR
  else if (currentState == STATE_ERROR) {
    // Check OFF button
    if (off_button_pressed()) {
      enter_off_state();
      unsigned long db = millis();
      while (millis() - db < 200);
      return;
    }

    // RESET button -> reinitialize and return to IDLE
    if (reset_button_pressed()) {
      log_event("RESET pressed - reinitializing sensors");
      mpuError = false;
      mpu_init();
      unsigned long db = millis();
      while (millis() - db < 200);
      enter_idle_state();
      return;
    }
  }
}
