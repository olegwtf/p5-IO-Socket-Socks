#!/usr/bin/perl

use lib "blib/lib";
use IO::Socket::Socks;
use IO::Select;
use FileHandle;

$| = 1;

my $socks = new IO::Socket::Socks(ProxyAddr=>"127.0.0.1",
                                  ProxyPort=>"8888",
                                  SocksDebug=>0,
                                  Listen=>1,
                                  RequireAuth=>1,
                                  UserAuth=>\&auth
                                 );

print $socks,"\n";

my $select = new IO::Select($socks);
        
while(1)
{
    if ($select->can_read())
    {
        my $client = $socks->accept();

        if (!defined($client))
        {
            print "ERROR: $SOCKS_ERROR\n";
            next;
        }

        my $command = $client->command();
        if ($command->[0] == 1)
        {
            print "connect!\n";
            $client->command_reply(0,"127.0.0.1","4000");
        }
        
        my $buff;
        $client->sysread($buff,1024);
        print $buff,"\n";
        $client->close();
    }
}
        
print $socks,"\n";


sub auth
{
    my $user = shift;
    my $pass = shift;

    print "user($user) pass($pass)\n";

    return 1 if (($user eq "foo") && ($pass eq "bar"));
    return 0;
}


