import threading
from decnet.timers import *
import time

def tmo (arg):
    print ("timeout callback,", arg)
    
c = CallbackTimer (tmo, "hello")

print ("asking for callback in 3 seconds")
timers.start (c, 3)

print ("waiting 5 seconds")
time.sleep (5)
print ("done waiting")

timers.shutdown ()
print ("timers shut down")
