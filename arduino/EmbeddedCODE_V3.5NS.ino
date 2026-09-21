#include <Wire.h>
#include "Adafruit_VL53L0X.h"

Adafruit_VL53L0X laser;

void setup()
{
  Serial.begin(115200);

  // SDA = D20, SCL = D21
  Wire.begin();

  Serial.println("Проверка лазерного дальномера VL53L0X...");

  if (!laser.begin())
  {
    Serial.println("VL53L0X не найден!");
    Serial.println("Проверь SDA D20, SCL D21, VCC и GND.");

    while (true)
    {
      delay(1000);
    }
  }

  Serial.println("VL53L0X успешно подключён.");
}

void loop()
{
  VL53L0X_RangingMeasurementData_t measurement;

  laser.rangingTest(&measurement, false);

  if (measurement.RangeStatus != 4)
  {
    Serial.print("Расстояние: ");
    Serial.print(measurement.RangeMilliMeter);
    Serial.print(" мм / ");
    Serial.print(measurement.RangeMilliMeter / 10.0);
    Serial.println(" см");
  }
  else
  {
    Serial.println("Нет корректного измерения");
  }

  delay(300);
}
