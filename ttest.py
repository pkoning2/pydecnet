from decnet.timers import *
import time

def tmo (arg):
    print "timeout callback,", arg
    
c = CallbackTimer (tmo, "hello")

timers.start (c, 3)

print "waiting 5 seconds"
time.sleep (5)
print "done waiting"

timers.shutdown ()
print "timers shut down"
