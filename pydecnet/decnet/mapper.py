#!

"""DECnet/Python map server

"""

# External packages used:
#
# Leaflet from https://github.com/Leaflet/Leaflet
# Leaflet.Arc from https://github.com/MAD-GooZe/Leaflet.Arc
# Leaflet.Dialog from https://github.com/NBTSolutions/Leaflet.Dialog
#  Dialog uses FontAwesome icons, licensed under Creative Commons
#  Attribution 4.0 license: https://fontawesome.com/license

import datetime
import json
import re
import os
import socket
import collections
try:
    import pytz
    utc = pytz.utc
except ImportError:
    pytz = None

# For some reason datetime.strptime does an import at runtime.  Make
# that happen now so we have the resulting internal module imported
# before any chroot is done.
datetime.datetime.strptime("2020", "%Y")

from .common import *
from . import html
from . import statemachine
from . import session
from . import logging
from . import timers
from . import nicepackets
from . import events
from .nsp import UnknownNode, WrongState, NSPException

resdir = os.path.join (DECNETROOT, "resources")

MapperUser = session.EndUser1 (name = "NETMAPPER")
NICEVERSION = ( 4, 0, 0 )

ENDNODES = (nicepackets.ENDNODE3, nicepackets.ENDNODE4)
PHASE3 = (nicepackets.ROUTING3, nicepackets.ENDNODE3)

STARTDELAY = 60
NICETIMEOUT = 60
MAXPARPOLL = 20
MAXINCPOLL = MAXPARPOLL
INCHOLDOFF = 15

DAY = 86400
SCANINTERVAL = 1 * DAY
DBUPDATEINTERVAL = 1 * DAY
# We can't actually set a timeout for 7 days.  Instead, check every
# CHECKINTERVAL whether it has been long enough since the past poll or
# node database update.
CHECKINTERVAL = 1200

H_GONE = 0
H_FADE = 1
H_DOWN = 2
H_UP = 3

FADE_TIME = 14 * DAY
GONE_TIME = 60 * DAY

ROCKALL = (57.596306, -13.687306)

def east (l, l2 = ROCKALL):
    # Compare with longitude more significant.
    return (l[1], l[0]) > (l2[1], l2[0])

notime = "&nbsp;" * 10
def strflocaltime (utcts):
    # Convert a Unix time value (UTC timestamp) to a date/time string
    # representation of the local time, with zone name included.
    if not utcts:
        return notime
    ret = datetime.datetime.fromtimestamp (utcts, utc)
    return ret.astimezone ().strftime ("%d-%b-%Y %H:%M %Z")

def page_title (title, tsscan = 0, tsdb = 0, tsinc = 0, links = ()):
    tsscan = strflocaltime (tsscan)
    tsdb = strflocaltime (tsdb)
    spaces = "&nbsp;" * 4
    if tsinc:
        tsinc = "Last incremental change {}{}".format (strflocaltime (tsinc),
                                                       spaces)
    else:
        tsinc = ""
    ll = (("/", "Home"),) + links
    links = ''.join (spaces + '<a href="{}">{}</a>'.format (*l) for l in ll)
    return html.top (title, "Node DB last updated {}{}Network data last updated {}{}{}{}".format (tsdb, spaces, tsscan, spaces, tsinc, links))
    
# DEF_LOC is the geographic coordinates we use for nodes for which the
# database does not give a location.
DEF_LOC = (-37.3, -12.68)        # Inaccessible Island, h/t to Daniel Suarez
NOLOC = "(Location not listed)"  # Location "name" for that case

MAPBODYHDR = '''
<div id="map" class="netmap">
  <script>
var osm = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
  })

var OpenTopoMap = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
	maxZoom: 17,
	attribution: 'Map data: &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors, <a href="http://viewfinderpanoramas.org">SRTM</a> | Map style: &copy; <a href="https://opentopomap.org">OpenTopoMap</a> (<a href="https://creativecommons.org/licenses/by-sa/3.0/">CC-BY-SA</a>)'
});

var Esri_WorldImagery = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community'
});

var Esri_WorldStreetMap = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Source: Esri, DeLorme, NAVTEQ, USGS, Intermap, iPC, NRCAN, Esri Japan, METI, Esri China (Hong Kong), Esri (Thailand), TomTom, 2012'
});

var Esri_WorldTopoMap = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ, TomTom, Intermap, iPC, USGS, FAO, NPS, NRCAN, GeoBase, Kadaster NL, Ordnance Survey, Esri Japan, METI, Esri China (Hong Kong), and the GIS User Community'
});


  var tip = L.Point([12,41]);

  var redIcon = L.icon ({iconUrl: '/resources/images/marker-icon-red.png',
		shadowUrl:     '/resources/images/marker-shadow.png',
		iconSize:    [25, 41],
		iconAnchor:  [12, 41],
		popupAnchor: [1, -34],
		tooltipAnchor: [16, -28],
		shadowSize:  [41, 41]});
  var greenIcon = L.icon ({iconUrl: '/resources/images/marker-icon-green.png',
		shadowUrl:     '/resources/images/marker-shadow.png',
		iconSize:    [25, 41],
		iconAnchor:  [12, 41],
		popupAnchor: [1, -34],
		tooltipAnchor: [16, -28],
		shadowSize:  [41, 41]});
  var yellowIcon = L.icon ({iconUrl: '/resources/images/marker-icon-yellow.png', 
		shadowUrl:     '/resources/images/marker-shadow.png',
		iconSize:    [25, 41],
		iconAnchor:  [12, 41],
		popupAnchor: [1, -34],
		tooltipAnchor: [16, -28],
		shadowSize:  [41, 41]});
  var grayIcon = L.icon ({iconUrl: '/resources/images/marker-icon-gray.png', 
		shadowUrl:     '/resources/images/marker-shadow.png',
		iconSize:    [25, 41],
		iconAnchor:  [12, 41],
		popupAnchor: [1, -34],
		tooltipAnchor: [16, -28],
		shadowSize:  [41, 41]});
'''

# Read map pane documentation HTML content.  This is inserted into the
# JavaScript code for the map display, as the content of a popup
# dialog box.  It would be nice to do this with <embed > or <iframe >
# but that produces its own framing and scroll bar, rather than
# obeying the one of the (resizable) dialog box.  So we'll do it this
# way.  It just means that a change in the documentation text has no
# effect until the PyDECnet process is restarted, since the
# documentation is loaded only at startup.
with open (os.path.join (resdir, "mapdoc.html"), "rt") as f:
    mapdoc = f.read ()

# Similarly, read the documentation content that is inserted into the
# map data table HTML.
with open (os.path.join (resdir, "mapdatadoc.html"), "rt") as f:
    mapdatadoc = f.read ()

MAPBODYEND = """
  var map = L.map('map', {layers: [osm, l2places, l2paths,
      l1places, l1paths]}).setView([45, -20], 3);

L.control.scale().addTo(map);

var basemaps = { "OpenStreetMap" : osm,
  "OpenTopoMap" : OpenTopoMap,
  "ESRI World Imagery" : Esri_WorldImagery,
  "ESRI World Street Map" : Esri_WorldStreetMap,
  "ESRI World Topo Map" : Esri_WorldTopoMap
 };

var overlaymaps = { "Core Node locations" : l2places,
  "Backbone Paths" : l2paths,
  "Level 1 Node locations" : l1places,
  "Level 1 Paths" : l1paths };

L.control.layers (basemaps, overlaymaps).addTo (map);

var doctext = %r;

var mapdoc = L.control.dialog ({ initOpen: false,
  anchor: [ 50, 50 ],
  size: [ 500, 400 ],
  maxSize: [ 1500, 1500 ] })
  .setContent (doctext);

/* Adapted from Leaflet.Control.Zoom */
  var DocButton = L.Control.extend({
  	// @section
  	// @aka Control.DocButton options
  	options: {
  		position: 'topleft',
  		DocText: '?',
  		DocTitle: 'Map documentation'
  	},

  	onAdd: function (map) {
  		var docName = 'mapper-control-mapdoc',
  		    container = L.DomUtil.create('div', docName + ' leaflet-bar'),
  		    options = this.options;

  		this._docButton  = this._createButton(options.DocText, options.DocTitle,
  		        docName + '-in',  container, this._doc);
        this._map = map;

  		return container;
  	},

  	onRemove: function (map) {
  	},

  	disable: function () {
  		this._disabled = true;
  		this._updateDisabled();
  		return this;
  	},

  	enable: function () {
  		this._disabled = false;
  		this._updateDisabled();
  		return this;
  	},

  	_doc: function (e) {
  		if (!this._disabled) {
            mapdoc.addTo (this._map);
  			mapdoc.open();
  		}
  	},

  	_createButton: function (html, title, className, container, fn) {
  		var link = L.DomUtil.create('a', className, container);
  		link.innerHTML = html;
  		link.href = '#';
  		link.title = title;

  		/*
  		 * Will force screen readers like VoiceOver to read this as "Doc in - button"
  		 */
  		link.setAttribute('role', 'button');
  		link.setAttribute('aria-label', title);

  		L.DomEvent.disableClickPropagation(link);
  		L.DomEvent.on(link, 'click', L.DomEvent.stop);
  		L.DomEvent.on(link, 'click', fn, this);
  		L.DomEvent.on(link, 'click', this._refocusOnMap, this);

  		return link;
  	},

  	_updateDisabled: function () {
  		var className = 'leaflet-disabled';

  		L.DomUtil.removeClass(this._docButton, className);

  		if (this._disabled) {
  			L.DomUtil.addClass(this._docButton, className);
  		}
  	}
  });

new DocButton ().addTo (map);

</script></div>""" % mapdoc

dtr_re = re.compile (r"(.+?): +(.+)")

class mapcirctable (html.table):
    def __init__ (self, data):
        super ().__init__ ("", data)

class mapdatarow (html.detailrow):
    detailtable = mapcirctable
    detailclass = "mapdetails"

class mapdatatable (html.detail_table):
    rclass = mapdatarow
    
class MapLocation:
    def __init__ (self, name, loc):
        self.name = name
        self.loc = tuple (loc)
        self.nodes = dict ()
        self.bb = False
        
    def __eq__ (self, other):
        return self.loc == other.loc
    
    def __ne__ (self, other):
        return self.loc != other.loc

    def __lt__ (self, other):
        return self.loc < other.loc

    def __gt__ (self, other):
        return self.loc > other.loc
    
    def __format__ (self, off):
        off = off or "0"
        off = int (off) * 360
        return "[{},{}]".format (self.loc[0], self.loc[1] + off)

    def add (self, node):
        # "node" is a MapNode instance
        self.nodes[node] = node
            
    def color (self):
        c = collections.Counter ()
        for n in self.nodes.values ():
            c[n.health ()] += 1
        t = max (c)
        if t == H_UP:
            # Looks green, but check for red or yellow
            if c[H_DOWN]:
                if c[H_DOWN] < c[H_UP]:
                    return "yellow"
                return "red"
        return self.h2color (t)

    @staticmethod
    def h2color (t):
        return ("gray", "gray", "red", "green")[t]

    def actnodes (self):
        d = collections.defaultdict (list)
        for n in self.nodes.values ():
            k = Nodeid (n.id)
            h = n.health ()
            # Unlike circuits, treat very old nodes as faded so they
            # do show up.
            if h == H_GONE:
                h = H_FADE
            d[h].append ((k, n.name))
        tip = list ()
        pop = list ()
        for h in sorted (d, reverse = True):
            tip2 = list ()
            pop2 = list ()
            for k, v in d[h]:
                if v:
                    s = '<span class="hs{}">{}&nbsp;({})</span>'.format (h, k, v)
                else:
                    s = '<span class="hs{}">{}</span>'.format (h, k)
                pop2.append (s)
                if h != H_FADE:
                    tip2.append (s)
            if tip2:
                tip.append (" ".join (tip2))
            if pop2:
                pop.append (" ".join (pop2))
        return "<br>".join (tip), "<br>".join (pop)
    
    def marker (self):
        tip, pop = self.actnodes ()
        if tip:
            if self.loc == DEF_LOC:
                # Don't list uncharted unseen nodes
                pop = tip
            tip = self.name + "<br>" + tip
        if pop:
            pop = self.name + "<br>" + pop
        else:
            pop = self.name
        dp = ".bindPopup('{}')".format (pop)
        if tip:
            dt = ".bindTooltip('{}')".format (tip)
        else:
            dt = ""
        ret = [ "L.marker({}, {{icon: {}Icon}}){}{}"
                .format (self, self.color (), dp, dt) ]
        if east (self.loc):
            ret.append ("L.marker({:-1}, {{icon: {}Icon}}){}{}"
                        .format (self, self.color (), dp, dt))
        else:
            ret.append ("L.marker({:1}, {{icon: {}Icon}}){}{}"
                        .format (self, self.color (), dp, dt))
        return ",\n".join (ret)

class MapPath:
    def __init__ (self, loc1, loc2, bb = False):
        loc1 = tuple (loc1)
        loc2 = tuple (loc2)
        if east (loc1, loc2):
            loc1, loc2 = loc2, loc1
        self.loc = (loc1, loc2)
        self.bb = bb
        self.conns = dict ()

    def __eq__ (self, other):
        return self.loc == other.loc
    
    def __ne__ (self, other):
        return self.loc != other.loc

    def __lt__ (self, other):
        return self.loc < other.loc

    def __gt__ (self, other):
        return self.loc > other.loc
    
    def __format__ (self, off):
        off = off or "0"
        off = int (off) * 360
        l1, l2 = self.loc
        lat1, long1 = l1
        lat2, long2 = l2
        long1 += off
        long2 += off
        # For some reason, arcs that cross the 180 degree meridian
        # only draw correctly if done from the eastern to the western
        # (positive to negative longitude) points..  For others it
        # doesn't matter.
        if long1 < long2:
            lat1, long1, lat2, long2 = lat2, long2, lat1, long1
        return "[{},{}],[{},{}]".format (lat1, long1,
                                         lat2, long2)

    def add (self, id1, id2, adj):
        # id1 and id2 are the node IDs of the endpoints, adj is a MapAdj.
        if id1 > id2:
            id1, id2 = id2, id1
        k = (id1, id2)
        # Connections may be added multiple times, because both ends
        # participate and also because we don't distinguish redundant
        # connections between nodes.  We'll track the healthiest of
        # the opinions.
        try:
            oldh = self.conns[k].health ()
        except KeyError:
            oldh = H_GONE
        if oldh < adj.health ():
            self.conns[(id1, id2)] = adj

    def color (self):
        c = collections.Counter ()
        for n in self.conns.values ():
            c[n.health ()] += 1
        t = max (c)
        if t == H_UP:
            # Looks green, but check for red or yellow
            if c[H_DOWN]:
                if c[H_DOWN] < c[H_UP]:
                    return "yellow"
                return "red"
        # Unlike locations, a circuit that's very old (more than half
        # a year) is considered nonexistent and won't be displayed at
        # all.
        return (None, "gray", "red", "green")[t]

    def actconns (self):
        d = collections.defaultdict (list)
        for k, a in self.conns.items ():
            n1, n2 = k
            n1 = m.nodes[n1]
            n2 = m.nodes[n2]
            h = a.health ()
            # If it's H_GONE (really old) don't show it any longer
            if h:
                d[h].append ((n1.id, n1.name, n2.id, n2.name))
        tip = list ()
        pop = list ()
        for h in sorted (d, reverse = True):
            tip2 = list ()
            pop2 = list ()
            for i1, n1, i2, n2 in d[h]:
                i1 = Nodeid (i1)
                i2 = Nodeid (i2)
                if n1:
                    i1 = "{}&nbsp;({})".format (i1, n1)
                if n2:
                    i2 = "{}&nbsp;({})".format (i2, n2)
                s = '<span class="hs{}">{}-{}</span>'.format (h, i1, i2)
                pop2.append (s)
                if h != H_FADE:
                    tip2.append (s)
            if tip2:
                tip.append (" ".join (tip2))
            if pop2:
                pop.append (" ".join (pop2))
        return "<br>".join (tip), "<br>".join (pop)
    
    def draw (self):
        if self.bb:
            width = 2
        else:
            width = 1
        tip, pop = self.actconns ()
        if not pop:
            return ""
        dp = ".bindPopup('{}')".format (pop)
        if tip:
            dt = ".bindTooltip('{}')".format (tip)
        else:
            dt = ""
        c = self.color ()
        if not c:
            return ""
        # Always start with the connection between the base
        # coordinates.
        ret = [ 'L.Polyline.Arc({}, {{vertices: 100, color: "{}", weight: {}, linecap:"butt"}}){}{}'.format (self, c, width, dp, dt) ]
        if abs (self.loc[1][1] - self.loc[0][1]) > 180 \
           or east (self.loc[0]):
            # If the path crosses the 180 degree meridian, the
            # canonical coordinates result in a path going from plus
            # longitude to the right.  We'll create a second arc on
            # the left.  We also put in an alias arc on the left if
            # the base path is in the eastern hemisphere
            ret.append ('L.Polyline.Arc({:-1}, {{vertices: 100, color: "{}", weight: {}, linecap:"butt"}}){}{}'.format (self, c, width, dp, dt))
        elif not east (self.loc[1]):
            # If the path is in the western hemisphere, create an
            # alias to the right.
            ret.append ('L.Polyline.Arc({:1}, {{vertices: 100, color: "{}", weight: {}, linecap:"butt"}}){}{}'.format (self, c, width, dp, dt))
        return ",\n".join (ret)

class MapItem:
    def __init__ (self):
        self.last_seen = self.last_down = self.last_up = 0

    def update (self, up, ts):
        """Update this map item to be up (True) or down (False) at the
        supplied timestamp.  If it is already in that state, nothing
        happens.  If the state is different, the last up or last down
        timestamp is set.

        For up (True), the last_seen value is updated whether this is a
        change or not.

        Return value is True if this item changed from down to up, False
        in all other cases.
        """
        if up:
            self.last_seen = ts
            if self.last_up <= self.last_down:
                self.last_up = ts
                maplogger.trace ("Setting {} to up at {}", self, ts)
                return True
        else:
            if self.last_up > self.last_down:
                self.last_down = ts
                maplogger.trace ("Setting {} to down at {}", self, ts)
        return False

    def health (self):
        # Return one of the H_* health code values
        if self.last_up > self.last_down:
            return H_UP
        dtime = m.lastscan - self.last_down
        if dtime > GONE_TIME:
            return H_GONE
        if dtime > FADE_TIME:
            return H_FADE
        return H_DOWN

    def testdown (self, ts):
        # Mark item as down if it wasn't seen in the poll starting at "ts"
        if self.last_seen < ts:
            self.update (False, ts)
        
class MapAdj (MapItem):
    def __init__ (self, circ, tonode):
        super ().__init__ ()
        self.circ = circ
        self.tonode = tonode
        self.last_seen = self.last_down = self.last_up = 0

    def __str__ (self):
        return "adj {} to {}".format (self.circ, self.tonode)

    def sortkey (self):
        return (self.circ, self.tonode)
    
    def __hash__ (self):
        return hash (self.sortkey ())

    def __eq__ (self, other):
        return self.sortkey () == other.sortkey ()

    def __lt__ (self, other):
        return self.sortkey () < other.sortkey ()

def decode_neighbors (l):
    ret = dict ()
    for n in l:
        n["tonode"] = Nodeid (n["tonode"])
        a = MapAdj ("", 0)
        a.__dict__.update (n)
        ret[(n["circ"], n["tonode"])] = a
    return ret

class MapNode (MapItem):
    def __init__ (self, name, num, ntype, loc = "", ident = ""):
        super ().__init__ ()
        self.name = name
        self.id = NiceNode (num, name)
        self.adj = dict ()
        self.loc = loc
        self.type = ntype
        self.ident = ident
        
    def __str__ (self):
        return str (self.id)
    
    def sortkey (self):
        return self.id
    
    def __hash__ (self):
        return hash (self.sortkey ())

    def __eq__ (self, other):
        return self.sortkey () == other.sortkey ()

    def __lt__ (self, other):
        return self.sortkey () < other.sortkey ()

    def encode_json (self):
        ret = obj2dict (self)
        ret["adj"] = list (self.adj.values ())
        return ret

    def testdown (self, ts):
        # Check if this node, and any of its adjacencies, should be
        # marked as "down"
        super ().testdown (ts)
        for a in self.adj.values ():
            a.testdown (ts)
    
def obj2dict (o):
    ret = dict ()
    for k in dir (o):
        if not k.startswith ("_"):
            v = getattr (o, k, None)
            if v is not None and not callable (v):
                ret[k] = v
    return ret

class MapJsonEncoder (json.JSONEncoder):
    def __init__ (self):
        super ().__init__ (allow_nan = False, indent = 2,
                           separators = (',', ' : '))
        
    def default (self, o):
        # Use the JSON encoder of the class if there is one
        try:
            return o.encode_json ()
        except AttributeError:
            pass
        if isinstance (o, set):
            return list (o)
        # Encode other objects using their "dir"
        ret = obj2dict (o)
        if ret:
            return ret
        return super ().default (o)

class Mapdata:
    def __init__ (self, fn):
        self.nodes = dict ()
        self.nodenames = dict ()
        self.locnames = dict ()
        self.locations = dict ()
        self.fn = fn
        self.lastupdate = self.lastscan = self.lastinc = 0

    def addloc (self, loc):
        "Add a location, or return the one that's already there if name match"
        try:
            return self.locnames[loc.name]
        except KeyError:
            pass
        self.locnames[loc.name] = loc
        self.locations[loc.loc] = loc
        return loc
    
    def addnode (self, node):
        try:
            old = self.nodes[node.id]
            oldname = old.name
            for k, v in node.__dict__.items ():
                if k != "id" and v is not None:
                    setattr (old, k, v)
            if oldname != old.name:
                # Name changed, update names dictionary
                del self.nodenames[oldname]
                self.nodenames[old.name] = old
        except KeyError:
            self.nodes[node.id] = node
            maplogger.trace ("{} added as new node", node.id)
            if node.name:
                # It has a name, enter that (overriding a previous
                # entry for that name if there was one)
                try:
                    old = self.nodenames[node.name]
                    maplogger.trace ("deleting old entry {} for name {}",
                                   old.id, node.name)
                    del self.nodes[old.id]
                except KeyError:
                    pass
                self.nodenames[node.name] = node
        
    def save (self):
        # We don't want to lose data.  So write the new state to a new
        # file, and only if that worked rename the current one to
        # backup and the new one to current.  If something goes wrong,
        # issue a critical level log message and turn off the mapper.
        enc = MapJsonEncoder ()
        try:
            with open (self.fn + ".new", "wt") as f:
                f.write (enc.encode (self.encode_json ()))
            try:
                os.rename (self.fn, self.fn + "~")
            except OSError:
                pass
            os.rename (self.fn + ".new", self.fn)
        except Exception:
            logging.critical ("Map data write failure", exc_info = True)
            raise

    def load (self):
        try:
            with open (self.fn, "rt") as f:
                s = f.read ()
        except OSError:
            maplogger.info ("No map database found, using null data")
            return
        self.decode_json (s)
        if not self.lastupdate:
            self.lastupdate = max (n.time for n in self.nodes)
        
    def encode_json (self):
        return dict (nodes = [ v for k, v in sorted (self.nodes.items ()) ],
                     lastupdate = self.lastupdate,
                     lastscan = self.lastscan,
                     lastincremental = self.lastinc)

    def decode_json (self, s):
        d = json.loads (s)
        # Reinitialize
        self.__init__ (self.fn)
        for n in d["nodes"]:
            name = n.get ("name", "")
            ntype = n.get ("type", None)
            nn = MapNode (name, Nodeid (n["id"]), ntype)
            for k, v in n.items ():
                if k == "latlong":
                    v = tuple (v)
                if k == "adj":
                    v = decode_neighbors (v)
                if k not in ("name", "id"):
                    setattr (nn, k, v)
            self.nodes[nn.id] = nn
            self.nodenames[nn.name] = nn
        self.lastupdate = d.get ("lastupdate", 0)
        self.lastscan = d.get ("lastscan", 0)
        self.lastinc = d.get ("lastincremental", 0)

# The request messages are global data since they never change.
# Read exec characteristics
execchar = nicepackets.NiceReadNode ()
# Entity: node number, executor (number 0)
execchar.entity = nicepackets.NodeReqEntity (0, 0)
execchar.info = 2    # Characteristics
# Ditto but for Phase II
p2exec = nicepackets.P2NiceReadExecStatus ()
# Read known circuits.  (Known, not active, so we can get the set of
# configured circuits and remove any that are no longer defined on the
# node.)
knocirc = nicepackets.NiceReadCircuit ()
# Entity: known circuits
knocirc.entity = nicepackets.CircuitReqEntity (-1)
knocirc.info = 1    # Status
# Ditto but for Phase II
p2line = nicepackets.P2NiceReadLineStatus ()
p2line.entity = nicepackets.P2LineEntity ("*")
# Read active nodes
actnode = nicepackets.NiceReadNode ()
# Entity: active nodes
actnode.entity = nicepackets.NodeReqEntity (-2)
actnode.info = 1    # Status

m = None

class PollDone (Work):
    "Reports completion of a NodePoller to its parent"
    
class NodePoller (Element, statemachine.StateMachine):
    # Small state machine to collect NICE data from a single node.
    def __init__ (self, parent, mapnode, pollts):
        Element.__init__ (self, parent)
        statemachine.StateMachine.__init__ (self)
        self.pollts = pollts
        self.curnode = mapnode
        self.nodeid = mapnode.id
        self.conn = None
        # Keep track of other nodes we have seen
        self.todo = set ()
        # Get the state machine moving
        self.node.addwork (Work (self))
        
    def s0 (self, item):
        self.scport = session.InternalConnector (self.node.session,
                                                 self, "NETMAPPER")
        try:
            maplogger.trace ("Connecting to NML at {}", self.curnode)
            # We'll request proxy.  That doesn't seem to do anything
            # useful with VMS, so if default access is not enabled the
            # result will be an authentication failure.  I still don't
            # know how to make it work with VMS proxy.
            self.conn = self.scport.connect (self.nodeid, 19, NICEVERSION,
                                             localuser = MapperUser,
                                             proxy = True)
            # Note that we don't need to set a timer at this
            # point, because NSP guarantees that a connect request
            # will be answered in bounded time (with a "timeout"
            # reject message, if necessary).
            return self.connecting
        except UnknownNode:
            maplogger.error ("Unknown node {}", nodeid)
        return self.finished ()

    def connecting (self, item):
        # Expecting accept (or reject)
        if isinstance (item, session.Accept):
            # Ok, we're connected
            self.curnode.update (True, self.pollts)
            if not item.message:
                # No connect data, so Phase II
                self.phase2 = True
                self.nmlversion = "Phase II"
            else:
                self.phase2 = False
                try:
                    self.nmlversion = Version (item.message)
                except Exception:
                    self.nmlversion = None
            maplogger.trace ("connection made to {}, NML version {}",
                           self.curnode, self.nmlversion)
            # Issue the read exec characteristics
            if self.phase2:
                return self.next_request (p2exec, self.procp2exec, "Phase II executor")
            return self.next_request (execchar, self.procexec, "Executor characteristics")
        elif isinstance (item, session.Reject):
            maplogger.trace ("connection to {} rejected, reason {}, data {}",
                             self.curnode, item.reason, item.message)
            if item.reason not in (session.UNREACH, session.OBJ_FAIL):
                # Node was reachable but the connection was not
                # accepted, perhaps a Cisco node or NML disabled.
                # Call it reachable.
                #
                # Note we don't treat OBJ_FAIL as reachable, because
                # it is the code used for connect timeout.  While that
                # typically means the destination had a problem, it
                # can be due to network issues where the "unreachable,
                # return-to-sender" isn't delivered.
                self.curnode.update (True, self.pollts)
            # We're done (and we don't have a connection at the moment)
            self.conn = None
            return self.finished ()

    def polling (self, item):
        if isinstance (item, session.Data):
            if self.phase2:
                if self.respcount is None:
                    # First message, the status and response count
                    retcode = item.message[0]
                    if retcode > 127:
                        retcode -= 256
                    if retcode != 1:
                        # Error return, give up now
                        maplogger.trace ("Poll {} received error {}: {}",
                                         self.nodeid, retcode, item.message)
                        return self.finished ()
                    try:
                        msg = nicepackets.P2NiceReply3 (item.message)
                    except Exception:
                        maplogger.exception ("Error parsing first message: {}",
                                             item.message)
                        return self.finished ()
                    self.respcount = msg.count
                else:
                    # NICE data packet.
                    try:
                        msg = self.replyclass (item.message)
                        maplogger.trace ("Poll {} received Phase II msg {}",
                                         self.nodeid, msg)
                    except Exception:
                        maplogger.exception ("Error parsing as {}: {}",
                                           self.replyclass, item.message)
                        return self.finished ()
                    self.replies.append (msg)
                    # Count down packets remaining
                    self.respcount -= 1
                if self.respcount:
                    self.node.timers.start (self, NICETIMEOUT)
                    return
                else:
                    # Done with the replies for this request, handle it.
                    return self.handler (self.replies)
            # First just look at the retcode field, because some
            # messages (code 2 and -128 for example) have no payload
            # and won't parse if we try to treat them as a full read
            # information reply.  In fact, some systems don't even
            # send the detail field in that case, so we can't even
            # parse it using the NiceReply (header) layout.
            retcode = item.message[0]
            if retcode > 127:
                retcode -= 256
            if retcode == -128:
                maplogger.trace ("Poll {} received end (-128)", self.nodeid)
                ret = False
            elif retcode < 0:
                # Error return, give up now
                maplogger.trace ("Poll {} received error {}",
                                 self.nodeid, retcode)
                return self.finished ()
            elif retcode == 2:
                # Indicator that multiple messages are coming
                maplogger.trace ("Poll {} received multiple header (-2)",
                                 self.nodeid)
                assert not self.replies
                self.mult = True
                ret = True
            else:
                try:
                    msg = self.replyclass (item.message)
                    maplogger.trace ("Poll {} received code {} msg {}",
                                     self.nodeid, retcode, msg)
                except Exception:
                    maplogger.exception ("Error parsing as {}: {}",
                                       self.replyclass, item.message)
                    return self.finished ()
                self.replies.append (msg)
                ret = self.mult
            if ret:
                self.node.timers.start (self, NICETIMEOUT)
                return
            else:
                # Done with the replies for this request, handle it.
                return self.handler (self.replies)
        elif isinstance (item, session.Disconnect):
            maplogger.trace ("Poll {} disconnected, reason {}, data {}",
                             self.nodeid, item.reason, item.message)
            self.conn = False
        elif isinstance (item, timers.Timeout):
            # Timeout.  It would be nice to keep going but that isn't
            # doable because we're out of sync with the other side
            # now.  We might end up receiving a reply for a previous
            # request, and since the replies are not self-describing
            # we'd get all messed up in the parsing.
            maplogger.debug ("Timeout waiting for reply from {}", self.curnode)
        else:
            maplogger.debug ("Unexpected item {}".format (item))
        return self.finished ()
        
    def next_request (self, req, handler, what):
        # Set up the next request
        maplogger.trace ("Poll {} requesting {}", self.nodeid, what)
        if not self.phase2:
            # We don't use payloads in the requests we send
            req.payload = b""
        try:
            self.conn.send_data (req)
        except NSPException:
            return self.finished ()
        self.handler = handler
        self.replies = list ()
        self.replyclass = req.replyclass
        self.mult = False
        self.respcount = None
        self.node.timers.start (self, NICETIMEOUT)
        return self.polling

    def finished (self):
        if self.conn:
            try:
                self.conn.disconnect ()
            except WrongState:
                pass
        maplogger.trace ("Poll {} finished", self.nodeid)
        # Tell the parent we're done.
        done = PollDone (self.parent, nodeid = self.nodeid, todo = self.todo)
        self.node.addwork (done)
        # Stop any timer
        self.remove ()

    def procexec (self, ret):
        # Handle completion of read exec characteristics
        if len (ret) == 1:
            ret = ret[0]
            # Save the information we want from the received
            # characteristics.  Start with node type.  That's a required
            # argument, but Linux doesn't necessarily send it.
            nt = getattr (ret, "type", None)
            self.curnode.type = nt
            self.curnode.ident = getattr (ret, "identification", "")
            if not self.curnode.name:
                # We don't know the name.  Use what the node tells us.
                try:
                    self.curnode.name = ret.entity.nodename
                except Exception:
                    pass
        else:
            maplogger.error ("{} replies to read exec char from {}",
                           len (ret), self.nodeid)
        return self.next_request (knocirc, self.procknocirc, "Known circuits")

    def procp2exec (self, ret):
        # Handle completion of Phase II read exec status
        if len (ret) == 1:
            ret = ret[0]
            # Save the information we want from the received
            # status.  
            self.curnode.ident = ret.system
            # We now know its node type.  We don't do this just based
            # on the NML version at connect, because sometimes a
            # malfunctioning Linux node will accept the connection
            # without version data and then show it's broken by not
            # sending a valid NICE reply.  Such nodes of course are
            # not Phase II...
            self.curnode.type = nicepackets.PHASE2
            if not self.curnode.name:
                # We don't know the name.  Use what the node tells us.
                try:
                    self.curnode.name = ret.name
                except Exception:
                    pass
        else:
            maplogger.error ("{} replies to read exec char from {}",
                           len (ret), self.nodeid)
        return self.next_request (p2line, self.procp2line, "Known lines")
        
    def procknocirc (self, ret):
        # Handle completion of read known circuits
        circuits = set ()
        for r in ret:
            circ = str (r.entity)
            circuits.add (circ)
            nodeid = getattr (r, "adjacent_node", None)
            if nodeid:
                # There is a neighbor
                nodeid = Nodeid (nodeid[0])
                a = self.parent.mapadj (self.curnode, circ, nodeid)
                nowup = a.update (True, self.pollts)
                if a.tonode.area != self.nodeid.area and \
                   self.curnode.type != 3:
                    # It is a cross-area adjacency, that means both
                    # ends are area routers.  Force that and log it,
                    # but only if we hadn't done so already.
                    self.curnode.type = 3    # Area router
                    maplogger.trace ("Marking node {} as area router",
                                     self.curnode)
                # Unlike the active nodes status, we don't get the
                # adjacent node type returned in circuit status, so we
                # have to visit it.  Do so for a full network scan, or
                # if this circuit/adj up event actually changed the
                # state from down to up.
                if self.parent.fullscan or nowup:
                    self.todo.add (nodeid)
        # Now create a new adjacency dictionary containing only
        # adjacencies for circuits that were "known" this time around.
        self.curnode.adj = { k : v for (k, v) in self.curnode.adj.items ()
                             if k[0] in circuits }
        if self.nodeid == self.parent.nodeid:
            # This poll is for the mapper node itself.  Don't run
            # active nodes scan because that will show as active all
            # the nodes that we're trying to poll (in parallel)
            # because they have connections, but some of those
            # connections will fail because the node is not actually
            # reachable.  There may be more elegant solutions, but
            # simply skipping the node poll on the mapper node should
            # cure most of the issue.
            #
            # It would be tempting to replace the "active nodes" query
            # by "adjacent nodes", but RSTS badly messes up the
            # implementation of that request.
            return self.finished ()
        return self.next_request (actnode, self.procactnode, "Active nodes")

    def procp2line (self, ret):
        # Handle completion of Phase II read known lines
        circuits = set ()
        for r in ret:
            circ = str (r.entity)
            circuits.add (circ)
            nodename = r.adjacent_node
            if nodename:
                # There is a neighbor node name, look it up
                try:
                    n = m.nodenames[nodename]
                except KeyError:
                    # We have a name but don't know the number...
                    n = MapNode (nodename, 0, None)
                nodeid = n.id                    
                a = self.parent.mapadj (self.curnode, circ, nodeid)
                nowup = a.update (True, self.pollts)
                # If we're doing a full network scan, or if this
                # circuit/adj up event actually changed the state from
                # down to up.
                if self.parent.fullscan or nowup:
                    self.todo.add (nodeid)
        # That's all we can ask of Phase II nodes
        return self.finished ()

    def procactnode (self, ret):
        # Handle completion of read active nodes
        for r in ret:
            # Pick up some attributes
            nodeid = Nodeid (r.entity)
            nodename = getattr (r.entity, "nodename", "")
            ntype = getattr (r, "adj_type", None)
            circ = getattr (r, "adj_circuit", None)
            links = getattr (r, "active_links", 0)
            hops = getattr (r, "hops", None)
            # Some implementations will report "active" nodes when the
            # node had a connection in the past.  Those don't have a
            # neighbor type, or hops, or a non-zero link count.
            if ntype is None and links == 0 and hops is None:
                continue
            # Since it's reachable, we will mark it and plan to
            # visit it
            n = self.parent.mapnode (nodeid, nodename)
            n.update (True, self.pollts)
            # See if it's a neighbor and its type was given.
            #### Bug workaround: we'd like to use the type, if this
            #### node is a neighbor node.  Unfortunately RSTS includes
            #### the type even if the node is not adjacent.  To make
            #### matters worse, it has the wrong value, at least some
            #### of the time, for example showing an area router as L1
            #### and vice versa.  Until this is understood and fixed
            #### the best option is to ignore the adjacent node type
            #### field.
            if False: # ntype is not None and circ:
                # It's a neighbor, update its adjacency
                a = self.parent.mapadj (self.curnode, circ, nodeid)
                a.update (True, self.pollts)
                # And set the neighbor's type
                if n.type != ntype:
                    maplogger.trace ("Updating node {} type from {} to {}",
                                     n, n.type, ntype)
                n.type = ntype
                # In some cases, there is no point in trying to poll the
                # neighbor.  If it's Phase II or out of area Phase III,
                # we can't talk to it.  We do scan endnodes even though
                # at this point we know its type and reachability, so we
                # can get its circircuit state.  That's not for the map
                # image but for the map data table.
                if ntype in PHASE3 and nodeid.area != self.nodeid.area \
                   or ntype == nicepackets.PHASE2:
                    self.parent.done.add (nodeid)
                    continue
            # Reachable node, we want to poll it
            if self.parent.fullscan:
                self.todo.add (nodeid)
        # No more requests
        return self.finished ()

# Decorator for Mapper methods that handle DECnet event messages.
handlers = dict ()
def handler (evt):
    def h (f):
        handlers[evt] = f
        return f
    return h

class Mapper (Element, statemachine.StateMachine):
    def __init__ (self, config, nodelist):
        # At startup we do a full update once, then periodically
        # thereafter.
        self.forcedbupdate = self.forcescan = True
        # We need some node to be the parent; pick the first DECnet
        # node in the list of nodes running in this PyDECnet instance.
        for n in nodelist:
            if n.decnet:
                break
        else:
            raise ValueError ("Mapper needs a DECnet node")
        Element.__init__ (self, n)
        statemachine.StateMachine.__init__ (self)
        self.config = config
        self.nodelist = nodelist
        if not pytz:
            raise ValueError ("Mapper requires pytz module")
        self.dbtz = pytz.timezone (config.nodedbtz)
        self.nodeid = n.routing.nodeid
        self.todo = set ()
        self.done = set ()
        self.polls = set ()
        self.started = None
        self.fullscan = False
        self.incremental = False
        self.title = "{} map server on {}".format (config.mapper,
                                                   n.routing.nodeinfo)
        self.datatitle = "{} map data on {}".format (config.mapper,
                                                     n.routing.nodeinfo)
        # Do a dummy getaddrinfo to load whatever is needed for that
        # to work later on, after chroot.
        socket.getaddrinfo ("google.com", 80)

    def start (self):
        global m, maplogger
        # Create our logger.  We do that here rather than earlier to
        # make sure it happens after any chroot.
        maplogger = logging.getLogger ("decnet.mapper")
        # Load the map database
        m = Mapdata (self.config.mapdb)
        m.load ()
        maplogger.info ("Starting network mapper service")
        # Build the map HTML based on what we just loaded from the
        # saved data.
        self.update_map ()
        # Register as a logging monitor
        monevt = set ((evt.event_class, evt.event_code) for evt in handlers)
        for n in self.nodelist:
            n.register_monitor (self, monevt)
        # All set, get the mapper going in one minute
        self.node.timers.start (self, STARTDELAY)

    def handleEvent (self, evt):
        if self.fullscan:
            # Ignore events while a full scan is underway
            return
        try:
            h = handlers[type (evt)]
            maplogger.trace ("Dispatching monitor event {}", evt)
            nowts = Timestamp ().startts ()
            h (self, evt, nowts)
        except KeyError:
            pass

    @staticmethod
    def getadjnode (evt):
        try:
            adj = evt.adjacent_node
        except AttributeError:
            # Some implementations send a "node" attribute instead
            adj = evt.node
        # If it's a local event, we get a node object.  For one received
        # from a remote sender, it's a CMNode field which is a tuple
        # with the node ID in the first element.
        if isinstance (adj, nicepackets.CMNode):
            adj = adj[0]
        return Nodeid (adj)

    @handler (events.circ_down)
    @handler (events.circ_fault)
    @handler (events.circ_off)
    @handler (events.adj_down)
    @handler (events.adj_oper)
    def circ_down (self, evt, nowts):
        # Circuit down and adjacency down type events all have circuit
        # and adjacent node information, so we treat them as equivalent.
        src = evt.source
        node = self.mapnode (src)
        circ = str (evt.entity_type)
        adj = self.getadjnode (evt)
        adjnode = self.mapnode (adj)
        maplogger.trace ("circuit {} to {} down on {}", circ, adjnode, node)
        try:
            aent = self.mapadj (node, circ, adj)
            aent.update (False, nowts)
        except KeyError:
            print (str (node.adj))
            maplogger.trace ("no map entry for {} {}", circ, adj)
        # Try to scan both endpoints of the circuit/adj that came up
        self.todo.add (src)
        self.todo.add (adj)
        # Do an incremental update
        self.incremental = True
        self.node.timers.start (self, INCHOLDOFF)

    @handler (events.circ_up)
    @handler (events.adj_up)
    def circ_up (self, evt, nowts):
        src = evt.source
        node = self.mapnode (src)
        circ = str (evt.entity_type)
        adj = self.getadjnode (evt)
        adjnode = self.mapnode (adj)
        maplogger.trace ("circuit {} to {} up on {}", circ, adjnode, node)
        try:
            aent = self.mapadj (node, circ, adj)
            aent.update (True, nowts)
        except KeyError:
            maplogger.trace ("no map entry for {} {}", circ, adj)
        # Scan both endpoints of the circuit/adj that came up
        self.todo.add (src)
        self.todo.add (adj)
        # Do an incremental update
        self.incremental = True
        self.node.timers.start (self, INCHOLDOFF)

    @handler (events.reach_chg)
    def reach_chg (self, evt, nowts):
        nodeid = Nodeid (evt.entity_type)
        node = self.mapnode (nodeid)
        if evt.status == 0:
            # Reachable.  Poll this node to get its data
            maplogger.trace ("Node {} reachable", node)
            self.todo.add (nodeid)
        else:
            # Unreachable
            maplogger.trace ("Node {} unreachable", node)
            node.update (False, nowts)
        # Either way we'll do an incremental update
        self.incremental = True
        self.node.timers.start (self, INCHOLDOFF)

    # Since the mapper does not track areas, we do not look for area
    # reachability change events.

    def s0 (self, item):
        now = Timestamp ()
        nowts = now.startts ()
        if self.forcedbupdate or m.lastupdate + DBUPDATEINTERVAL < nowts:
            # Time to run a database update
            self.forcedbupdate = False
            return self.startdbupdate ()
        return self.checkmapscan ()

    def startdbupdate (self):
        maplogger.info ("Starting mapping database update")
        # Update defaults to incremental.  As of 5/1/2020, the
        # timestamp is the last-modified timestamp (originally it was
        # the creation timestamp).
        self.dbthread = threading.Thread (target = self.dbupdate,
                                          daemon = True)
        self.dbthread.start ()
        return self.dbupdating

    def dbupdating (self, item):
        # Update the map, that will refresh the map/data page with the
        # current node information
        self.update_map ()
        # Now go run the map scan, if it is time for that
        return self.checkmapscan ()
        
    def checkmapscan (self):
        now = Timestamp ()
        nowts = now.startts ()
        if self.node.routing.isolated ():
            maplogger.debug ("Skipping scan since mapper is isolated")
        elif self.forcescan or m.lastscan + SCANINTERVAL < nowts:
            self.forcescan = False
            maplogger.info ("Starting mapper full network scan")
            # Initialize the traversal data.  Begin with all currently
            # known nodes that are not (a) phase III nodes in another
            # area, or recorded as endnodes or Phase II nodes.  But
            # always include the local node in case we have an
            # incomplete (or even empty) map database.
            self.first_poll = True
            self.todo = { self.nodeid }
            for k, n in m.nodes.items ():
                nt = getattr (n, "type", None)
                if not (nt in (0, 1) and n.id.area != self.nodeid.area 
                        or nt == 2):
                    self.todo.add (k)
            # Record the poll start time.  We use this for every
            # updated time stamp, rather than the actual time we visit
            # a particular entity.
            self.started = now
            self.fullscan = True
            self.incremental = False
            m.lastscan = self.pollts = nowts
            return self.nextnode ()
        elif self.incremental:
            # Incremental scan requested.  The "todo" set has been
            # filled by event handlers with the set of nodes to be
            # polled (if any).  Sometimes no polling is needed; that
            # happens if all the changes are loss of connectivity.
            # But we still want to start the state machine so we'll
            # end up at finish_poll where the map is updated.
            maplogger.info ("Starting mapper incremental update, {} nodes",
                          len (self.todo))
            self.first_poll = False
            self.started = now
            m.lastinc = self.pollts = nowts
            return self.nextnode ()
        # Nothing to do, wait and check again in a while
        self.node.timers.start (self, CHECKINTERVAL)
        return self.s0
        
    def polling (self, item):
        # Waiting for a node poll to complete
        if not isinstance (item, PollDone):
            return
        nodeid = item.nodeid
        todo = item.todo
        try:
            self.polls.remove (nodeid)
        except KeyError:
            # In case it has already been removed.  Not sure why that
            # might happen but it's been seen once, and it does no
            # harm to ignore it.
            pass
        # Add to the to-be-visited list whatever the poller found
        self.todo |= todo
        # Look for another node to poll
        return self.nextnode ()
    
    def nextnode (self):
        # Find the next not yet processed node to query, and start a
        # poll on it.
        if self.fullscan:
            limit = MAXPARPOLL
        else:
            limit = MAXINCPOLL
        while self.todo and len (self.polls) < limit:
            nodeid = self.todo.pop ()
            if nodeid in self.done:
                # We already visited this one, look for another
                continue
            # Mark this node as visited
            nodeid = Nodeid (nodeid)
            self.done.add (nodeid)
            self.polls.add (nodeid)
            curnode = self.mapnode (nodeid)
            poller = NodePoller (self, curnode, self.pollts)
        if self.polls:
            # Some polls were started, wait for them to complete
            return self.polling
        # Nothing left to do.  Is this the first part of the poll
        # (non-endnodes only)?
        if self.first_poll:
            self.first_poll = False
            # Put all the nodes (their node IDs) in the "todo" list.
            # That will visit whoever hasn't been visited or seen yet.
            # This often is a NOP, but it will update the data for any
            # node that has changed since the last poll.
            self.todo = set (m.nodes)
            return self.nextnode ()
        # If we reach this point, we've finished the map scan.
        self.finish_poll ()
        self.update_map ()
        # Start the check timer
        self.node.timers.start (self, CHECKINTERVAL)
        # and go to idle state
        return self.s0

    def finish_poll (self):
        # Finish up the poll.
        # Reset the poll state back to the initial values
        if self.fullscan:
            what = "full"
            how = maplogger.info
        else:
            what = "incremental"
            how = maplogger.debug
        self.todo = set ()
        self.done = set ()
        self.polls = set ()
        # If we did a full scan, mark anything as down that wasn't
        # seen in the scan.  Save the data.  Report a summary of what
        # was found.
        up = down = 0
        for n in m.nodes.values ():
            if self.fullscan:
                n.testdown (self.pollts)
            if n.health () == H_UP:
                up += 1
            else:
                down += 1
        self.fullscan = False
        self.incremental = False
        try:
            m.save ()
        except Exception:
            # Stop the timer so no further updates will happen.
            self.node.timers.stop (self)
        how ("Network {} scan took {}, map has {} total nodes, {} up, {} down",
             what, self.started, up + down, up, down)
            
    def mapnode (self, nodeid, name = "", ntype = None):
        try:
            ret = m.nodes[nodeid]
        except KeyError:
            # Odd, a reachable node not mentioned in the node
            # database.  Make up a database entry for it, with a name
            # if we know it.
            logging.trace ("mapnode: adding missing node {} ({}) type {}", nodeid, name, ntype)
            ret = MapNode (name, nodeid, ntype)
            m.addnode (ret)
        return ret
    
    def mapadj (self, n, circ, nodeid):
        circ = str (circ)
        try:
            adj = n.adj[(circ, nodeid)]
        except KeyError:
            # An adjacency we haven't seen before.
            adj = MapAdj (circ, nodeid)
            n.adj[(circ, nodeid)] = adj
        return adj
        
    def html (self, mobile, parts):
        "Returns a tuple: title, top, and body"
        if parts == [ ]:
            return self.title, self.top, self.mapbody
        if parts == [ "data" ]:
            return self.datatitle, self.top, self.databody
        return None, None, None
    
    def update_map (self):
        locations = dict ()
        l2paths = dict ()
        l1paths = dict ()
        nodedata = list ()
        nodehdr = [ "Node", "Type", "Location", "Last down", "Last up", "Identification" ]
        for k, n in sorted (m.nodes.items ()):
            l1 = getattr (n, "latlong", DEF_LOC)
            # Add this node to the location
            try:
                l = locations[l1]
            except KeyError:
                locations[l1] = l = MapLocation (n.loc or NOLOC, l1)
            l.add (n)
            t = getattr (n, "type", None)
            try:
                ts = nicepackets.rvalues[t]
            except (TypeError, IndexError):
                ts = "unknown"
            ld = strflocaltime (n.last_down)
            lu = strflocaltime (n.last_up)
            nh = n.health ()
            noderow = [ '<span class="hs{}">{}</span>'.format (nh, NiceNode (n.id, n.name)), ts, n.loc, ld, lu, n.ident ]
            circuits = list ()
            for k, a in sorted (n.adj.items ()):
                try:
                    n2 = m.nodes[a.tonode]
                    l2 = n2.latlong
                    ln = n2.loc
                except (AttributeError, KeyError):
                    # Other end is not a known node or has no
                    # lat/long, supply the placeholder location
                    # (Inaccessible Island).
                    l2 = DEF_LOC
                    ln = ""
                ch = a.health ()
                tonode = self.mapnode (a.tonode)
                crow = [ '<span class="hs{}">{}</span>'.format (ch, a.circ),
                         '<span class="hs{}">{}</span>'.format (ch, NiceNode (tonode.id, tonode.name)),
                         ln, strflocaltime (a.last_down), strflocaltime (a.last_up) ]
                circuits.append (crow)
                if l1 == l2:
                    # Endpoints match, nothing to draw
                    continue
                tonode = self.mapnode (a.tonode)
                try:
                    ll = locations[l2]
                except KeyError:
                    locations[l2] = ll = MapLocation (tonode.loc or NOLOC, l2)
                if l1 < l2:
                    k = (l1, l2)
                else:
                    k = (l2, l1)
                # Add this circuit to the path
                if n.type == nicepackets.AREA and n2.type == nicepackets.AREA:
                    # Backbone connection
                    paths = l2paths
                    # Mark the endpoints as being backbone sites
                    l.bb = ll.bb = True
                else:
                    paths = l1paths
                try:
                    c = paths[k]
                except KeyError:
                    paths[k] = c = MapPath (l1, l2, bb = paths is l2paths)
                c.add (n.id, a.tonode, a)
            if circuits:
                noderow.append (circuits)
            else:
                noderow.append (None)
            nodedata.append (noderow)
        l1markers = [ l.marker () for l in locations.values () if not l.bb ]
        l2markers = [ l.marker () for l in locations.values () if l.bb ]
        # And the paths
        l1arcs = list ()
        l2arcs = list ()
        for arcs, paths in (l1arcs, l1paths), (l2arcs, l2paths):
            for p in paths.values ():
                a = p.draw ()
                if a:
                    arcs.append (a)
        body = """
  var l1places = L.layerGroup ([ {} ]);
  var l1paths  = L.layerGroup ([ {} ]);
  var l2places = L.layerGroup ([ {} ]);
  var l2paths  = L.layerGroup ([ {} ]);"""
        body = body.format (",\n".join (l1markers), ",\n".join (l1arcs),
                            ",\n".join (l2markers), ",\n".join (l2arcs))
        self.mapbody = MAPBODYHDR + body + MAPBODYEND
        doclink = '<p>Data table documentation is <a href="#mapdatadoc">here.</a></p><p></p>'
        tabletext = str (mapdatatable (nodehdr, nodedata))
        self.databody = html.section (self.datatitle,
                                      doclink + tabletext + mapdatadoc)
        maplinks = (("/map", "Network map"), ("/map/data", "Map data table"))
        if m.lastinc > m.lastscan:
            inc = m.lastinc
        else:
            inc = 0
        self.top = page_title (self.title,
                               links = maplinks, tsdb = m.lastupdate,
                               tsscan = m.lastscan, tsinc = inc)

    def strfdbtime (self, utcts):
        # Convert a Unix time value (UTC timestamp) to a date/time
        # string representation of the local time of the node database
        # server.
        ret = datetime.datetime.fromtimestamp (utcts, utc)
        return ret.astimezone (self.dbtz).strftime ("%d-%b-%Y %H:%M:%S")

    def strpdbtime (self, s):
        # Convert a time string in the local time of the database
        # server to a Unix time value.
        ret = datetime.datetime.strptime (s, "%d %b %Y %H:%M:%S")
        ret = self.dbtz.localize (ret)
        return ret.astimezone (utc).timestamp ()
    
    def dbupdate (self, full = False):
        # This runs in a separate thread, to get updated records from
        # the node database server (MIM).  When done, it starts a
        # short timeout which will deliver a Timeout work item to the
        # main state machine, allowing that state machine to clean up
        # the thread and proceed with other work.
        try:
            dtr = dtrf = None
            dtr = socket.create_connection ((self.config.nodedbserver, 1234))
            maplogger.debug ("Connected to database server at MIM")
            nodes = 0
            dtrf = dtr.makefile (mode = "r", encoding = "latin1")
            dtr.send (bytes (self.config.dbpassword + "\n", encoding = "latin1"))
            l = dtrf.readline ()
            l = l.rstrip ("\n")
            if l != "Ready":
                maplogger.warning ("Unexpected prompt: {}", l)
                return
            if full or m.lastupdate == 0:
                maplogger.debug ("Requesting full database")
                dtr.send (b"\n")
            else:
                ts = self.strfdbtime (m.lastupdate)
                maplogger.debug ("Requesting changes since {}", ts)
                dtr.send (bytes ('TIME > "{}"\n'.format (ts),
                                 encoding = "latin1"))
            name = addr = owner = timestamp = loc = None
            coord = (0, 0)
            for l in dtrf:
                l = l.rstrip ("\n")
                if l == "Done":
                    break
                rm = dtr_re.match (l)
                if not rm:
                    maplogger.warning ("Unexpected record in reply: {}", l)
                    continue
                k, v = rm.groups ()
                v = v.strip ()
                maplogger.trace ("database server: {}: {} ", k, v)
                if k == "Current time":
                    maplogger.trace ("Server current time is {}", v)
                    upd = self.strpdbtime (v)
                elif k == "Node":
                    # We expect "Node" to be the first field
                    if name and loc.lower () != "scrapped":
                        # This is not the first record.  Create a node
                        # and, if applicable, a place name, for the
                        # previous record.
                        nodes += 1
                        curnode = MapNode (name, addr, None, loc)
                        curnode.owner = owner
                        curnode.time = timestamp
                        if coord != (0, 0):
                            curnode.latlong = coord
                        m.addnode (curnode)
                        addr = owner = timestamp = loc = None
                        coord = (0, 0)
                    name = v
                elif k == "Address":
                    addr = Nodeid (v)
                elif k == "Owner":
                    owner = v
                elif k == "Time" or k == "Modified":
                    timestamp = self.strpdbtime (v)
                elif k == "Loc":
                    loc = v
                elif k == "Coord":
                    lat, long = v.split (",")
                    coord = (float (lat), float (long))
            if name and loc.lower () != "scrapped":
                # We have a final record.  Create a node and, if
                # applicable, a place name, for the previous record.
                nodes += 1
                curnode = MapNode (name, addr, None, loc)
                curnode.owner = owner
                curnode.time = timestamp
                if coord != (0, 0):
                    curnode.latlong = coord
                m.addnode (curnode)
            m.lastupdate = upd
            maplogger.debug ("{} node database entries updated", nodes)
        except Exception:
            maplogger.exception ("Error during map database update")
        finally:
            if dtrf:
                dtrf.close ()
            if dtr:
                dtr.close ()
            # Wake up the mapper in 5 seconds, that's plenty of time
            # for this thread to end.
            self.node.timers.start (self, 5)
            try:
                m.save ()
            except Exception:
                # Stop the timer so no further updates will happen.
                self.node.timers.stop (self)
