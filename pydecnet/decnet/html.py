#!

"""DECnet/Python HTML building classes

"""

from decnet.common import DNVERSION, DNREV

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

def wrap (content, cls):
    if isinstance (content, (str, wraphtml)):
        return content
    return cls (*content)

def makelink (path, title, qs = ""):
    return '<a href="/{}{}">{}</a>'.format (path, qs, title)
    
class thdr (wraphtml):
    open = "<tr><th>"
    close = "</th></tr>"
    sep = "</th><th>"

class trow (wraphtml):
    open = "<tr><td>"
    close = "</td></tr>"
    sep = "</td><td>"

class table (wraphtml):
    open = "<table>"
    close = "</table>"

    def __init__ (self, header, data):
        super ().__init__ (wrap (header, thdr),
                           *[ wrap (i, trow) for i in data])

class lines (wraphtml):
    open = "<p>"
    close = "</p>"
    sep = "<br>\n"
    
class div (wraphtml):
    open = "<div>"
    close = "</div>"

# Subclasses of div to change the class attribute (CSS style)
class middle (div): open = '<div class="middle">'
class sidebar (div): open = '<div class="sidebar">'
class sbelement (div): open = '<div class="sidebar-element">'
class sblabel (div): open = '<div class="sidebar-label">'
class main (div): open = '<div class="main">'

class sbbutton (div):
    open = '<div class="sidebar-link">'

    def __init__ (self, path, title = None, qs = ""):
        if title is None:
            super ().__init__ (path)
        else:
            super ().__init__ (makelink (path, title, qs))
    
class sbbutton_active (sbbutton): open = '<div class="sidebar-link-active">'

class section (div):
    open = '<div class="section">'

    def __init__ (self, title, body):
        super ().__init__ ("<h3>{}</h3>".format (title), body)

class tbsection (section):
    def __init__ (self, title, header, data):
        super ().__init__ (title, table (header, data))
        
class textsection (section):
    def __init__ (self, title, body):
        super ().__init__ (title, lines (*body))
        
class doc (object):
    def __init__ (self, title, middle):
        self.title = title
        self.middle = middle

    def __str__ (self):
        return """<html><head>
  <title>{0}</title>
  <link href="/resources/decnet.css" rel="stylesheet" type="text/css">
</head>
<body>
<div class="flex-page">
<div class="top">{0}</div>
{1}
<div class="footer">{2}-{3} &copy; 2013-2019 by Paul Koning</div>
</div>
</body></html>
""".format (self.title, self.middle, DNVERSION, DNREV)

