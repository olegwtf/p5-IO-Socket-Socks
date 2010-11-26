#!/usr/bin/perl

# Simple socks5 client
# gets google.com main page
# implemented with IO::Socket::Socks

use strict;
use IO::Socket::Socks;

# uncomment line below if you want to resolve hostnames locally
#$IO::Socket::Socks::SOCKS5_RESOLVE = 0;

my $socks = new IO::Socket::Socks(ProxyAddr=>"127.0.0.1",
                                  ProxyPort=>"1090",
                                  ConnectAddr=>"www.google.com",
                                  ConnectPort=>80,
                                  # uncomment lines below if you want to use authentication
                                  #Username=>"afoo",
                                  #Userpassword=>"123",
                                  #AuthType=>"userpass",
                                  SocksDebug=>1, # comment this if you are not interested in debug information
                                 )
or die $SOCKS_ERROR;

$socks->syswrite (
    "GET / HTTP/1.0\015\012".
    "Host: www.google.com\015\012\015\012"
);

while($socks->sysread(my $buf, 1024))
{
    print $buf;
}

# tested with server5.pl
