#!/usr/bin/awk

BEGIN {
    print "<html>"
    print "<head><title>CCDC Uptime</title></head>"
    print "<style type='text/css'>"
    print "img { "
    print "    float: left;"
    print "    margin-bottom: 15px;"
    print "    clear: both;"
    print "}</style></head>"
    print "<body>"
}

{
    printf "<img src='%s' />", $1
}

END {
    print "</body></html>"
}
