#!

"Version numbers for DECnet/Python, in various forms"

import subprocess

DNSTAGE = "V"
DNVERNUM = "1.1"
# Note: this must be incremented for each new kit released
DNPATCH = "0rc1"
CYEAR = "2024"
AUTHORS = "Paul Koning"

# Combined from parts above:
DNKITVERSION = f"{DNSTAGE}{DNVERNUM}.{DNPATCH}"

# At module load time, attempt to get the Git revision.  There might
# not be one, if this isn't a Git repository.
r = r = subprocess.run (["git", "log", "-1", "--pretty=%h"],
                        capture_output = True, universal_newlines = True)
if r.returncode:
    # Some error, we don't have a revision
    DNREV = None
    DNVERSION = DNKITVERSION
else:
    DNREV = r.stdout.rstrip ("\n")
    DNVERSION = f"{DNKITVERSION} ({DNREV})"

DNIDENT = f"DECnet/Python {DNVERSION}"
DNFULLVERSION = f"{DNIDENT} © 2013-{CYEAR} by {AUTHORS}"

