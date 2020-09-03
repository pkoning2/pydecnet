#!/usr/bin/env python3

"""Sketch of a DDCMP exerciser

Copyright (C) 2020 by Paul Koning

See LICENSE.txt
"""

# This file was created in response to an email asking whether
# PyDECnet DDCMP could be used as a test system to validate another
# implementation of DDCMP.  The answer is yes, in principle, but the
# PyDECnet design is not exactly a simple building blocks collection
# that can be run in isolation.
#
# To run a particular PyDECnet layer such as DDCMP, enough supporting
# scaffolding has to be created that it has the services it needs.
# Some of this can be seen, in very primitive form, in the test suite.
# That code is typically not functional but merely allows for calls to
# supporting APIs to be observed and checked (through the
# unittest.mock machinery).
#
# The code here was adapted by cut & paste from the main and node
# modules to show what the outline of a controller for the DDCMP data
# link, as a test driver, would look like.  There is no actual test
# code here, but there is startup code and logging, so if you run the
# code given here with trace logging enabled and with the DDCMP
# pointed to another DDCMP instance that is active, the DDCMP datalink
# will initialize and all that is visible in the logs.
#
# Similar techniques could be used to build test driver wrappers
# around other DECnet components.  The datalinks are the most obvious
# case; the other layers are less likely to be of interest in
# isolation but if someone wants to do that the example given here
# will give some hints on how to proceed.
#
# Note that using PyDECnet components as testers, which this example
# enables, provides an "interoperability test".  That is less rigorous
# than a protocol conformance test or a protocol validator.  A full
# validation of a protocol implementation requires dedicated test
# code, in order to exercise not just normal operation, but also error
# cases, timeout and retry handling, and so on.  An interoperability
# tests will not normally cover any of those cases, or at best only in
# a very cursory and non-systematic manner.
#
#        paul koning, 3 september 2020

import argparse
import threading
import queue

from decnet.common import *
from decnet import ddcmp
from decnet import logging
from decnet import timers
from decnet import datalink

class Tester (Element):
    def start (self):
        logging.debug ("Starting test driver")
        # todo: do something?

    def stop (self):
        logging.debug ("Stopping test driver")
        # Anything to do?

    def dispatch (self, item):
        # Pick up the DDCMP object for easy reference
        ddcmp = self.node.ddcmp
        logging.trace ("tester processing {}", item)
        # Todo: do something with the element.  Start with
        # "isinstance" to find out what it is, then log it or change
        # state or send a message
        
class MiniNode (Element):
    "A cut-down subset of decnet.Node"
    def __init__ (self, config):
        self.node = self
        self.config = config
        self.nodename = "TESTER"
        threading.current_thread ().name = self.nodename
        logging.debug ("Initializing node {}", self.nodename)
        self.timers = timers.TimerWheel (self, JIFFY, 3600)
        self.workqueue = queue.Queue ()
        # We now have a node.
        # Create its child entities in the appropriate order.
        self.tester = Tester (self)
        self.ddcmp = ddcmp.DDCMP (self.tester, "DDCMP", config)

    def addwork (self, work, handler = None):
        """Add a work item (instance of a Work subclass) to the node's
        work queue.  This can be called from any thread.  If "handler"
        is specified, set the owner of the work item to that value,
        overriding the handler specified when the Work object was created.
        """
        if handler is not None:
            work.owner = handler
        #logging.trace ("Add work {} of {}", work, work.owner)
        self.workqueue.put (work)
        
    def start (self, mainthread = False):
        """Start the node, i.e., its child entities in the right order
        and then the node main loop.
        """
        threading.current_thread ().name = self.nodename
        logging.debug ("Starting node {}", self.nodename)
        # First start the timer service in this node
        self.timers.startup ()
        # Now start all the elements
        self.ddcmp.port_open ()
        self.tester.start ()
        if mainthread:
            self.mainloop ()
        else:
            t = threading.Thread (target = self.mainloop, name = self.nodename)
            # Exit the server thread when the main thread terminates
            t.daemon = True
            t.start ()
            
    def mainloop (self):
        """Node main loop.  This is intended to be the main loop of
        the whole DECnet process, so it loops here and does not return
        until told to shut down.
        """
        q = self.workqueue
        try:
            while True:
                try:
                    work = q.get ()
                except KeyboardInterrupt:
                    break
                if isinstance (work, Shutdown):
                    break
                started = time.time ()
                logging.trace ("Dispatching {} of {}",
                               work, work.owner)
                work.dispatch ()
                dt = time.time () - started
                logging.trace ("Finished with {} of {}", work, work.owner)
        except Exception:
            logging.exception ("Exception caught in mainloop")
        finally:
            self.stop ()

    def stop (self):
        threading.current_thread ().name = self.nodename
        logging.debug ("Stopping node")
        # Stop things in the reverse order they are started
        self.tester.stop ()
        self.ddcmp.port_close ()
        self.timers.shutdown ()
    
dnparser = argparse.ArgumentParser ()
dnparser.add_argument ("device", help = "DDCMP device spec")
dnparser.add_argument ("--qmax", type = int, metavar = "Q",
                       default = 7, choices = range (1, 256),
                       help = "DDCMP max pending frame count (1..255, default 7)")
dnparser.add_argument ("-L", "--log-file", metavar = "FN",
                       help = "Log file (default: log to stderr)")
# Note that we set the default level to INFO rather than the conventional
# WARNING, so that events will get logged by default.
dnparser.add_argument ("-e", "--log-level", default = "INFO",
                       metavar = "LV",
                       choices = ("TRACE", "DEBUG", "INFO",
                                  "WARNING", "ERROR"),
                       help = "Log level (default: INFO)")
dnparser.add_argument ("--log-config", metavar = "LC",
                       help = "Logging configuration file")
dnparser.add_argument ("-k", "--keep", type = int, default = 0,
                       help = """Number of log files to keep with nightly
                              rotation.  Requires a log file name
                              to be specified.""")
dnparser.set_defaults (syslog = None, chroot = False, uid = 0, gid = 0)
dnparser.set_defaults (daemon = False)

def main ():
    """Main program.  Parses command arguments and instantiates the
    parts of DECnet.
    """
    p = dnparser.parse_args ()

    # First start up the logging machinery
    logging.start (p)

    logging.log (99, "Starting DDCMP tester")
    logging.info (" command line: {}".format (" ".join (sys.argv)))
    logging.flush ()

    node = MiniNode (p)
    
    # Start the node, in a thread of its own.
    node.start ()
    logging.flush ()
    logging.trace ("idling without http")
    while True:
        time.sleep (100)

if __name__ == "__main__":
    main ()
    
