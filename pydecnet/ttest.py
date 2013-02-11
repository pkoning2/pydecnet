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
    
c = CallbackTimer (tmo, "hello")

print ("asking for callback in 3 seconds")
node.timers.start (c, 3)

try:
    print ("Enter control/C to stop the test")
    time.sleep (3600)
except KeyboardInterrupt:
    node.addwork (Shutdown (node))
    time.sleep (1)
    if node.timers.is_alive ():
        print ("\ntimers still running?")
    else:
        print ("\ntimers shut down")
