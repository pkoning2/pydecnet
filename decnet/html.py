#!

"""DECnet/Python HTML building classes

"""

import time
from datetime import timedelta

def setstarttime ():
    global start_time
    start_time = time.time ()
    
class wraphtml (object):
    open = ""
    close = ""
    sep = "\n"

    def __init__ (self, *contents):
        self.contents = contents
        
    def __str__ (self):
        return self.open + \
               self.sep.join (str (i) for i in self.contents) + \
               self.close

def wrap1 (content, cls):
    if isinstance (content, wraphtml):
        return content
    return cls (content)

def wrap (content, cls):
    if isinstance (content, (str, wraphtml)):
        return content
    return cls (*content)

def makelink (mobile, path, title, qs = ""):
    return '<a href="/{}{}{}">{}</a>'.format ("m/" if mobile else "",
                                              path, qs, title)

class cell (wraphtml):
    tag = "td"
    align = ' valign="top" '
    markup = ""

    def __init__ (self, contents, markup = None, valign = None):
        super ().__init__ (contents)
        if markup:
            self.markup = markup
        if valign:
            self.align = ' valign="{}"'.format (valign)

    def __str__ (self):
        return '<{0.tag}{0.align}{0.markup}>{0.contents[0]}</{0.tag}>'.format (self)

class hcell (cell): tag = "th"

class trow (wraphtml):
    open = "<tr>"
    close = "</tr>"
    sep = ""
    cclass = cell

    def __init__ (self, *contents):
        super ().__init__ (*[ wrap1 (c, self.cclass) for c in contents ])

class thdr (trow): cclass = hcell

class drow (trow):
    def __init__ (self, col1, col2):
        super ().__init__ (cell (col1, 'class="td-col1"'),
                           cell (col2, 'class="td-col2"'))
    
class table (wraphtml):
    open = "<table>"
    close = "</table>"
    rclass = trow

    def __init__ (self, header, data):
        """Create an HTML table.  Arguments are the header and data.
        Header is a row of items, the column headers.  Data is a
        sequence of data rows.
        """
        super ().__init__ (wrap (header, thdr),
                           *[ wrap (i, self.rclass) for i in data])

class dtable (table):
    open = '<table class="tb-details">'
    rclass = drow

    def __init__ (self, data):
        super ().__init__ ("", data)

class detailrow (trow):
    detailtable = dtable
    detailclass = "details"
    
    def __init__ (self, *contents):
        *row1, extra = contents
        if extra:
            row1[0] = cell (row1[0], 'rowspan="2"')
            self.extra = self.detailtable (extra)
        else:
            self.extra = None
        super ().__init__ (*row1)
        
    def __str__ (self):
        line1 = super ().__str__ ()
        if self.extra:
            return '{}\n<tr><td colspan="{}" class="{}">{}</td></tr>' \
                    .format (line1, len (self.contents),
                             self.detailclass, self.extra)
        return line1
            
class detail_table (table):
    rclass = detailrow
    
class lines (wraphtml):
    open = "<p>"
    close = "</p>"
    sep = "<br>\n"
    
class div (wraphtml):
    open = "<div>"
    close = "</div>"

class pre (wraphtml):
    open = "<pre>"
    close = "</pre>"
    sep = "\n"
    
# Subclasses of div to change the class attribute (CSS style)
class middle (div): open = '<div class="middle">'
class sidebar (div): open = '<div class="sidebar">'
class sbelement (div): open = '<div class="sidebar-element">'
class sblabel (div): open = '<div class="sidebar-label">'
class main (div): open = '<div class="main">'
class toptitle (div): open = '<div class="toptitle">'
class timestamps (div): open = '<div class="timestamps">'

class mopdetails (div):
    open = '<div class="mop-details">'
    sep = "<br>\n"
    
class sbbutton (div):
    open = '<div class="sidebar-link">'

    def __init__ (self, mobile, path, title = None, qs = ""):
        if title is None:
            super ().__init__ (path)
        else:
            super ().__init__ (makelink (mobile, path, title, qs))
    
class sbbutton_active (sbbutton): open = '<div class="sidebar-link-active">'

class section (div):
    open = '<div class="section">'
    hdr = "h3"
    
    def __init__ (self, title, body):
        super ().__init__ ("<{0}>{1}</{0}>".format (self.hdr, title), body)

class firstsection (section): hdr = "h2"
    
class tbsection (section):
    def __init__ (self, title, header, data):
        """Return an HTML section with the supplied section title,
        followed by a table made from the header and data.
        """
        super ().__init__ (title, table (header, data))
        
class detail_section (section):
    def __init__ (self, title, header, data):
        super ().__init__ (title, detail_table (header, data))
        
class textsection (section):
    def __init__ (self, title, body):
        super ().__init__ (title, lines (*body))

class firsttextsection (textsection): hdr = "h2"
    
class presection (section):
    def __init__ (self, title, body):
        super ().__init__ (title, pre (*body))

class top (div):
    open = '<div class="top">'
    
    def __init__ (self, title, times):
        return super ().__init__ (toptitle (title), timestamps (times))

class footer (div):
    open = '<div class="footer">'
    
class doc (object):
    def __init__ (self, mobile, title, top, middle, bottom):
        self.mobile = mobile
        self.title = title
        self.top = top
        self.middle = middle
        self.bottom = bottom
        
    def __str__ (self, hdradd = ""):
        addmeta = ""
        if self.mobile:
            addmeta = \
'''<link href="/resources/decnet_m.css" rel="stylesheet" type="text/css">
<meta name="viewport" content="width=device-width, initial-scale=1">'''

        return """<html><head>
  <meta charset="UTF-8">
  <title>{0.title}</title>
  <link href="/resources/decnet.css" rel="stylesheet" type="text/css">
  {1}{2}
</head>
<body>
<div class="flex-page">
<div class="top">{0.top}</div>
{0.middle}
{0.bottom}
</body></html>
""".format (self, addmeta, hdradd)

#   <meta http-equiv="refresh" content="15">

class mapdoc (doc):
    "Similar to doc, but for maps"
    def __str__ (self):
        return super ().__str__ ('''
  <link rel="stylesheet" href="/resources/leaflet.css">
  <link rel="stylesheet" href="/resources/Leaflet.Dialog.css">
  <script src="/resources/leaflet.js"></script>
  <script src="/resources/leaflet-arc.min.js"></script>
  <script src="/resources/Leaflet.Dialog.js"></script>''')

def page_title (title, links = ()):
    now = time.time ()
    ts = time.strftime ("%d-%b-%Y %H:%M:%S %Z", time.localtime (now))
    spaces = "&nbsp;" * 4
    ll = (("/", "Home"),) + links
    links = ''.join (spaces + '<a href="{}">{}</a>'.format (*l) for l in ll)
    uptime = str (timedelta (int (now - start_time) / 86400.))
    return top (title, "Reported {}, up {}{}".format (ts, uptime, links))
    
    
