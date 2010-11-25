use IO::Socket::Socks;
use IO::Select;
use strict;

# return bind address as ip address like most socks5 proxyes does
$IO::Socket::Socks::SOCKS5_RESOLVE = 0;

# create socks server
my $server = IO::Socket::Socks->new(SocksVersion => 5, SocksDebug => 1, ProxyAddr => 'localhost', ProxyPort => 1090, Listen => 10, UserAuth => \&auth, RequireAuth => 1)
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
                # success
                $client->command_reply(0, $host, $port);
            }
            else
            {
                # Host Unreachable
                $client->command_reply(4, $host, $port);
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
{ # add `UserAuth => \&auth, RequireAuth => 1' to the server constructor if you want to authenticate user by login and password
    my $login = shift;
    my $password = shift;
    
    my %allowed_users = (root => 123, oleg => 321, ryan => 213);
    return $allowed_users{$login} eq $password;
}

# tested with `curl --socks5'
