#!/usr/bin/perl

# Simple socks4 server
# implemented with IO::Socket::Socks module

use IO::Socket::Socks;
use IO::Select;
use strict;

# allow socks4a protocol extension
$IO::Socket::Socks::SOCKS4_RESOLVE = 1;

# create socks server
my $server = IO::Socket::Socks->new(SocksVersion => 4, SocksDebug => 1, ProxyAddr => 'localhost', ProxyPort => 1090, Listen => 10)
    or die $SOCKS_ERROR;

# accept connections
while(1)
{
    my $client = $server->accept();
    
    if($client)
    {
        my ($cmd, $host, $port) = @{$client->command()};
        if($cmd == 1)
        { # connect
            # create socket with requested host
            my $socket = IO::Socket::INET->new(PeerHost => $host, PeerPort => $port, Timeout => 10);
            
            if($socket)
            {
                # request granted
                $client->command_reply(90, $host, $port);
            }
            else
            {
                # request rejected or failed
                $client->command_reply(91, $host, $port);
                $client->close();
                next;
            }
            
            my $selector = IO::Select->new($socket, $client);
            
            MAIN:
            while(1)
            {
                my @ready = $selector->can_read();
                foreach my $s (@ready)
                {
                    my $readed = $s->sysread(my $data, 1024);
                    unless($readed)
                    {
                        # error or socket closed
                        warn 'connection closed';
                        $socket->close();
                        last MAIN;
                    }
                    
                    if($s == $socket)
                    {
                        # return to client data readed from remote host
                        $client->syswrite($data);
                    }
                    else
                    {
                        # return to remote host data readed from the client
                        $socket->syswrite($data);
                    }
                }
            }
        }
        else
        {
            warn 'Unknown command';
        }
        
        $client->close();
    }
    else
    {
        warn $SOCKS_ERROR;
    }
}

sub auth
{ # add `UserAuth => \&auth' to the server constructor if you want to authenticate user by its id
    my $userid = shift;
    
    my %allowed_users = (root => 1, oleg => 1, ryan => 1);
    return exists($allowed_users{$userid});
}

# tested with `curl --socks4' and `curl --socks4a'
