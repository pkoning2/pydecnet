import threading
from decnet.node import *
from decnet.timers import *
import time

node = Node ()
if node.timers.is_alive ():
    print ("timers running")
else:
    print ("timers shut down")

def tmo (arg):
    print ("timeout callback,", arg)
    print ("Enter control/C to stop the test")
    
c = CallbackTimer (tmo, "hello")

print ("asking for callback in 3 seconds")
node.timers.start (c, 3)

try:
    node.run ()
except KeyboardInterrupt:
    if node.timers.is_alive ():
        print ("timers still running?")
    else:
        print ("timers shut down")
