#include <Servo.h>
#include <SPI.h>
#include <MFRC522.h>

//////////////////////////////////////////////
// RemoteXY
//////////////////////////////////////////////
#define REMOTEXY_MODE__HARDSERIAL
#define REMOTEXY_SERIAL Serial3
#define REMOTEXY_SERIAL_SPEED 9600

#include <RemoteXY.h>

#pragma pack(push, 1)
uint8_t PROGMEM RemoteXY_CONF[] =
{
  255,5,0,0,0,72,0,19,0,0,0,0,24,1,200,84,1,1,5,0,
  4,36,56,98,24,160,2,26,
  4,8,13,23,69,0,2,26,
  2,150,54,44,22,1,2,26,
  16,31,79,78,0,79,70,70,0,
  1,169,12,24,24,0,2,31,0,
  2,44,28,31,19,0,2,26,31,31,79,78,0,79,70,70,0
};

struct {
  int8_t Steering;     
  int8_t Throttle;     
  uint8_t Light; // Теперь эта кнопка включает КРАБОВЫЙ ХОД
  uint8_t Signal;      
  uint8_t Reversor;    
  uint8_t connect_flag;
} RemoteXY;
#pragma pack(pop)

//////////////////////////////////////////////
// ПИНЫ И ДАТЧИКИ
//////////////////////////////////////////////
const uint8_t FL_PWM_PIN = 3; const uint8_t FL_DIR_PIN = 22; 
const uint8_t FR_PWM_PIN = 4; const uint8_t FR_DIR_PIN = 23; 
const uint8_t RL_PWM_PIN = 5; const uint8_t RL_DIR_PIN = 24; 
const uint8_t RR_PWM_PIN = 6; const uint8_t RR_DIR_PIN = 25; 

const uint8_t FRONT_STEER_PIN = 7;
const uint8_t REAR_STEER_PIN = 8;

const uint8_t TRIG_PIN = 39;
const uint8_t ECHO_PIN = 41;

// --- ОСВЕЩЕНИЕ И ЗВУК ---
const uint8_t LIGHT_PIN = 34;
const uint8_t STOP_LIGHT_PIN = 46;  
const uint8_t LEFT_TURN_PIN = 42;   
const uint8_t RIGHT_TURN_PIN = 44;  
const uint8_t HORN_PIN = 32; 

// --- ДАТЧИК ХОЛЛА ---
const uint8_t HALL_PIN = 2; 

// --- АККУМУЛЯТОР ---
const uint8_t BATTERY_PIN = A1;

// --- RFID, EM ЗАМОК И RGB ---
const uint8_t RFID_SS_PIN = 53;
const uint8_t RFID_RST_PIN = A0;
const uint8_t EM_LOCK_PIN = 30;
const uint8_t RGB_GREEN_PIN = 35;
const uint8_t RGB_RED_PIN = 36;

MFRC522 mfrc522(RFID_SS_PIN, RFID_RST_PIN);

Servo frontServo;
Servo rearServo;

//////////////////////////////////////////////
// НАСТРОЙКИ МОТОРОВ И РУЛЯ
//////////////////////////////////////////////
float FL_TRIM = 0.92; float FR_TRIM = 1.0; 
float RL_TRIM = 0.845; float RR_TRIM = 0.92; 

const int FRONT_CENTER = 91;
const int REAR_CENTER = 91;
const int STEER_MAX = 70;
bool rearOpposite = true; // Переменная режима (true = нормальный руль, false = краб)

const int MAX_PWM = 180;
const int MIN_PWM = 25; 
const float DIFF_STRENGTH = 0.4; 

//////////////////////////////////////////////
// ПАРАМЕТРЫ ПОВОРОТНИКОВ И ЗАМКА
//////////////////////////////////////////////
unsigned long previousBlinkTime = 0;
const long blinkInterval = 500; 
bool turnLightState = false;

unsigned long unlockTimer = 0;
bool isUnlocked = false;
unsigned long denyTimer = 0;
bool isDenied = false;
bool isBatteryLow = false;

//////////////////////////////////////////////
// ПАРАМЕТРЫ КОЛЕСА И ОДОМЕТРИИ
//////////////////////////////////////////////
const float WHEEL_DIAMETER_M = 0.135; 
const float WHEEL_CIRCUMFERENCE = PI * WHEEL_DIAMETER_M; 
const float PULSES_PER_REV = 45.0; 

volatile unsigned long hallPulses = 0; 
float distanceTraveled = 0.0;

void countPulse() {
  hallPulses++;
}

void setup() {
  Serial.begin(9600); 
  RemoteXY_Init();

  SPI.begin();
  mfrc522.PCD_Init();

  pinMode(FL_DIR_PIN, OUTPUT); pinMode(FR_DIR_PIN, OUTPUT);
  pinMode(RL_DIR_PIN, OUTPUT); pinMode(RR_DIR_PIN, OUTPUT);
  
  pinMode(LIGHT_PIN, OUTPUT);
  pinMode(STOP_LIGHT_PIN, OUTPUT);
  pinMode(LEFT_TURN_PIN, OUTPUT);
  pinMode(RIGHT_TURN_PIN, OUTPUT);
  pinMode(HORN_PIN, OUTPUT); 
  digitalWrite(HORN_PIN, LOW);

  pinMode(EM_LOCK_PIN, OUTPUT);
  pinMode(RGB_GREEN_PIN, OUTPUT);
  pinMode(RGB_RED_PIN, OUTPUT);
  pinMode(BATTERY_PIN, INPUT);
  
  digitalWrite(EM_LOCK_PIN, LOW);
  digitalWrite(RGB_GREEN_PIN, LOW);
  digitalWrite(RGB_RED_PIN, LOW);

  pinMode(TRIG_PIN, OUTPUT); pinMode(ECHO_PIN, INPUT);

  pinMode(HALL_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(HALL_PIN), countPulse, RISING);

  frontServo.attach(FRONT_STEER_PIN);
  rearServo.attach(REAR_STEER_PIN);

  stopMotors();
  centerSteering();

  Serial.println(F("Система запущена. Кнопка Light переведена на крабовый ход."));
}

void loop() {
  RemoteXY_Handler();
  
  // Связываем кнопку Light из приложения с режимом руления
  // Если кнопка выключена (0) - обычный поворот (true)
  // Если кнопка включена (1) - крабовый ход (false)
  rearOpposite = (RemoteXY.Light == 0);
  
  distanceTraveled = (hallPulses / PULSES_PER_REV) * WHEEL_CIRCUMFERENCE;

  checkBattery();      
  processRFID();       
  updateAccessLogic(); 
  
  updateSteering();
  updateMotors();
  updateLights(); 
}

//////////////////////////////////////////////
// КОНТРОЛЬ АККУМУЛЯТОРА
//////////////////////////////////////////////
void checkBattery() {
  static unsigned long lastBatCheck = 0;
  
  if (millis() - lastBatCheck > 1000) {
    lastBatCheck = millis();
    
    int rawValue = analogRead(BATTERY_PIN);
    float voltage = rawValue * (5.0 / 1023.0);
    
    if (voltage <= 3.4) {
      isBatteryLow = true;
    } else if (voltage > 3.5) {
      isBatteryLow = false;
    }
  }
}

//////////////////////////////////////////////
// ЛОГИКА RFID И ДОСТУПА
//////////////////////////////////////////////
void processRFID() {
  if ( ! mfrc522.PICC_IsNewCardPresent()) return;
  if ( ! mfrc522.PICC_ReadCardSerial()) return;

  String content = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
     content.concat(String(mfrc522.uid.uidByte[i] < 0x10 ? "0" : ""));
     content.concat(String(mfrc522.uid.uidByte[i], HEX));
  }
  content.toUpperCase();
  
  Serial.print(F("Поднесена карта UID: "));
  Serial.println(content);

  if (content == "114D155D") {
    Serial.println(F("Доступ разрешен. Замок открыт на 10 сек."));
    digitalWrite(EM_LOCK_PIN, HIGH);   
    digitalWrite(RGB_GREEN_PIN, HIGH); 
    digitalWrite(RGB_RED_PIN, LOW); 
    
    isUnlocked = true;
    unlockTimer = millis();
    isDenied = false; 
  } else {
    Serial.println(F("Доступ запрещен!"));
    digitalWrite(RGB_GREEN_PIN, LOW);
    isDenied = true;
    denyTimer = millis();
  }

  mfrc522.PICC_HaltA(); 
}

void updateAccessLogic() {
  if (isUnlocked && (millis() - unlockTimer >= 10000)) {
    digitalWrite(EM_LOCK_PIN, LOW);
    digitalWrite(RGB_GREEN_PIN, LOW);
    isUnlocked = false;
    Serial.println(F("Замок закрыт по таймеру."));
  }

  if (isDenied) {
    digitalWrite(RGB_RED_PIN, HIGH);
    if (millis() - denyTimer >= 2000) {
      isDenied = false;
    }
  } else {
    if (isBatteryLow) {
      digitalWrite(RGB_RED_PIN, turnLightState); 
    } else {
      digitalWrite(RGB_RED_PIN, LOW);
    }
  }
}

//////////////////////////////////////////////
// ОСВЕЩЕНИЕ И СИГНАЛЫ
//////////////////////////////////////////////
void updateLights() {
  // 1. Основной свет включается автоматически при движении вперед
  if (!RemoteXY.Reversor && RemoteXY.Throttle >= 5) {
    digitalWrite(LIGHT_PIN, HIGH);
  } else {
    digitalWrite(LIGHT_PIN, LOW);
  }
  
  // 2. Стоп-сигнал
  if (RemoteXY.Signal || RemoteXY.Throttle < 5) {
    digitalWrite(STOP_LIGHT_PIN, HIGH);
  } else {
    digitalWrite(STOP_LIGHT_PIN, LOW);
  }

  unsigned long currentMillis = millis();
  if (currentMillis - previousBlinkTime >= blinkInterval) {
    previousBlinkTime = currentMillis;
    turnLightState = !turnLightState; 
  }

  // 3. Аварийка и поворотники
  if (RemoteXY.Signal) {
    digitalWrite(LEFT_TURN_PIN, turnLightState);
    digitalWrite(RIGHT_TURN_PIN, turnLightState);
    digitalWrite(HORN_PIN, HIGH);
  } 
  else {
    digitalWrite(HORN_PIN, LOW);
    
    if (RemoteXY.Steering > 50) {
      digitalWrite(RIGHT_TURN_PIN, turnLightState);
      digitalWrite(LEFT_TURN_PIN, LOW);
    } else if (RemoteXY.Steering < -50) {
      digitalWrite(LEFT_TURN_PIN, turnLightState);
      digitalWrite(RIGHT_TURN_PIN, LOW);
    } else {
      digitalWrite(LEFT_TURN_PIN, LOW);
      digitalWrite(RIGHT_TURN_PIN, LOW);
    }
  }
}

//////////////////////////////////////////////
// ФУНКЦИЯ УЗ ДАЛЬНОМЕРА
//////////////////////////////////////////////
long getFilteredUZ() {
  static unsigned long lastPing = 0;
  static long currentMedian = 250; 
  static long vals[3] = {250, 250, 250};
  static int index = 0;

  if (millis() - lastPing < 50) return currentMedian; 
  lastPing = millis();

  digitalWrite(TRIG_PIN, LOW); delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  detachInterrupt(digitalPinToInterrupt(HALL_PIN));
  long duration = pulseIn(ECHO_PIN, HIGH, 15000); 
  attachInterrupt(digitalPinToInterrupt(HALL_PIN), countPulse, RISING);

  long dist = (duration == 0) ? 250 : (duration * 0.034 / 2); 

  vals[index] = dist;
  index = (index + 1) % 3;

  long sorted[3] = {vals[0], vals[1], vals[2]};
  if (sorted[0] > sorted[1]) { long t = sorted[0]; sorted[0] = sorted[1]; sorted[1] = t; }
  if (sorted[1] > sorted[2]) { long t = sorted[1]; sorted[1] = sorted[2]; sorted[2] = t; }
  if (sorted[0] > sorted[1]) { long t = sorted[0]; sorted[0] = sorted[1]; sorted[1] = t; }

  currentMedian = sorted[1];
  return currentMedian;
}

//////////////////////////////////////////////
// ЛОГИКА ДВИЖЕНИЯ И ТОРМОЖЕНИЯ
//////////////////////////////////////////////
void updateMotors() {
  int throttle = RemoteXY.Throttle;
  int steer = RemoteXY.Steering;
  bool reverse = RemoteXY.Reversor;

  if(RemoteXY.Signal || throttle < 5) {
    stopMotors();
    printDebug(throttle, 250, 0, "СТОП");
    return;
  }

  int pwm = map(throttle, 0, 100, 0, MAX_PWM);
  int final_pwm = pwm; 
  long distUZ = 250;
  String debugStatus = rearOpposite ? "ПОВОРОТ" : "КРАБ";

  if (!reverse) {
    distUZ = getFilteredUZ(); 

    if (distUZ <= 100) {
      stopMotors();
      printDebug(throttle, distUZ, 0, "ЭКСТРЕННЫЙ ТОРМОЗ");
      return; 
    }
    else if (distUZ > 100 && distUZ <= 200) {
      final_pwm = map(distUZ, 100, 200, MIN_PWM, pwm);
      debugStatus += " + УЗ ЗАМЕДЛЯЕТ";
    }
  } else {
    debugStatus = "РЕВЕРС";
  }

  printDebug(throttle, distUZ, final_pwm, debugStatus);

  float left_diff = 1.0; float right_diff = 1.0;
  
  // ВАЖНО: Электронный дифференциал работает только при обычном повороте!
  // В режиме крабового хода колеса должны крутиться с одинаковой скоростью
  if (rearOpposite == true) {
    if (steer > 0) {
      right_diff = 1.0 - (DIFF_STRENGTH * (steer / 100.0));
    } else if (steer < 0) {
      left_diff = 1.0 - (DIFF_STRENGTH * (abs(steer) / 100.0));
    }
  }

  digitalWrite(FL_DIR_PIN, reverse ? LOW : HIGH);
  digitalWrite(RL_DIR_PIN, reverse ? LOW : HIGH);
  digitalWrite(FR_DIR_PIN, reverse ? HIGH : LOW);
  digitalWrite(RR_DIR_PIN, reverse ? HIGH : LOW);

  analogWrite(FL_PWM_PIN, final_pwm * FL_TRIM * left_diff);
  analogWrite(FR_PWM_PIN, final_pwm * FR_TRIM * right_diff);
  analogWrite(RL_PWM_PIN, final_pwm * RL_TRIM * left_diff);
  analogWrite(RR_PWM_PIN, final_pwm * RR_TRIM * right_diff);
}

//////////////////////////////////////////////
// ОТЛАДКА В ПОРТ
//////////////////////////////////////////////
void printDebug(int thr, long uz, int current_pwm, String status) {
  static unsigned long lastDebug = 0;
  if (millis() - lastDebug > 500) {
    lastDebug = millis();
    Serial.print(F("Газ: ")); Serial.print(thr);
    Serial.print(F("\t| УЗ(см): ")); Serial.print(uz);
    Serial.print(F("\t| ШИМ: ")); Serial.print(current_pwm); 
    
    if(isBatteryLow) Serial.print(F("\t| АКБ: РАЗРЯЖЕН"));
    else Serial.print(F("\t| АКБ: НОРМА"));
    
    Serial.print(F("\t| Статус: ")); Serial.println(status);
  }
}

//////////////////////////////////////////////
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
//////////////////////////////////////////////
void updateSteering() {
  int steer = RemoteXY.Steering;
  int front = map(steer, -100, 100, FRONT_CENTER - STEER_MAX, FRONT_CENTER + STEER_MAX);
  front = constrain(front, 0, 180);
  int delta = front - FRONT_CENTER;
  
  // Если rearOpposite = false (краб), задняя ось поворачивается туда же, куда и передняя (+ delta)
  int rear = rearOpposite ? (REAR_CENTER - delta) : (REAR_CENTER + delta);
  
  frontServo.write(front);
  rearServo.write(constrain(rear, 0, 180));
}

void stopMotors() {
  analogWrite(FL_PWM_PIN, 0); analogWrite(FR_PWM_PIN, 0);
  analogWrite(RL_PWM_PIN, 0); analogWrite(RR_PWM_PIN, 0);
}

void centerSteering() {
  frontServo.write(FRONT_CENTER);
  rearServo.write(REAR_CENTER);
}
