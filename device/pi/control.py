#!/usr/bin/python
import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)
GPIO.setup(14, GPIO.OUT)
GPIO.output(14, True)
time.sleep(5)
GPIO.output(14, False)
GPIO.cleanup()
