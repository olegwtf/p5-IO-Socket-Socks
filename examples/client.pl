#!/usr/bin/perl

use lib "blib/lib";
use IO::Socket::Socks;
use FileHandle;

$| = 1;

my $socks = new IO::Socket::Socks(ProxyAddr=>"127.0.0.1",
                                  ProxyPort=>"8888",
                                  ConnectAddr=>"127.0.0.1",
                                  ConnectPort=>7979,
                                  AuthType=>"userpass",
                                  #Username=>"12345678901234",
                                  #Password=>"bar",
                                  Username=>"afoo",
                                  Password=>"bar",
                                  SocksDebug=>0,
                                 );

if (!defined($socks))
{
    die($SOCKS_ERROR);
    exit(1);
}
print $socks,"\n";


print $socks "foo\n";

#&_send($socks,new FileHandle("/home/reatmon/.cshrc"));

$socks->close();



sub _send
{
    my $sock = shift;
    my $data = shift;

    if (ref($data) eq "")
    {
        my $length = length($data);
        my $offset = 0;
        while ($length != 0)
        {
            my $written = $sock->syswrite($data,$length,$offset);
            $length -= $written;
            $offset += $written;
        }
    }
    if (ref($data) eq "FileHandle")
    {
        while(my $temp = <$data>)
        {
            my $length = length($temp);
            my $offset = 0;
            while ($length != 0)
            {
                my $written = $sock->syswrite($temp,$length,$offset);
                $length -= $written;
                $offset += $written;
            }
        }
    }
}



