5##############################################################################
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Library General Public
#  License as published by the Free Software Foundation; either
#  version 2 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Library General Public License for more details.
#
#  You should have received a copy of the GNU Library General Public
#  License along with this library; if not, write to the
#  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
#  Boston, MA  02111-1307, USA.
#
#  Copyright (C) 2003 Ryan Eatmon
#
##############################################################################
package IO::Socket::Socks;

use strict;
use IO::Socket;
use IO::Select;
use Errno qw(EWOULDBLOCK);
use Carp;
use base qw( IO::Socket::INET );
use vars qw(@ISA @EXPORT $VERSION %CODES );
require Exporter;
@ISA = qw(Exporter IO::Socket::INET);
@EXPORT = qw( $SOCKS_ERROR );

$VERSION = "0.2";
our $SOCKS_ERROR;

use constant SOCKS5_VER =>  5;

use constant ADDR_IPV4       => 1;
use constant ADDR_DOMAINNAME => 3;
use constant ADDR_IPV6       => 4;

use constant CMD_CONNECT  => 1;
#use constant CMD_BIND     => 2;
#use constant CMD_UDPASSOC => 3;

use constant AUTHMECH_ANON     => 0;
#use constant AUTHMECH_GSSAPI   => 1;
use constant AUTHMECH_USERPASS => 2;
use constant AUTHMECH_INVALID  => 255;

$CODES{AUTHMECH}->[AUTHMECH_INVALID] = "No valid auth mechanisms";

use constant AUTHREPLY_SUCCESS  => 0;
use constant AUTHREPLY_FAILURE  => 1;

$CODES{AUTHREPLY}->[AUTHREPLY_FAILURE] = "Failed to authenticate";

use constant REPLY_SUCCESS             => 0;
use constant REPLY_GENERAL_FAILURE     => 1;
use constant REPLY_CONN_NOT_ALLOWED    => 2;
use constant REPLY_NETWORK_UNREACHABLE => 3;
use constant REPLY_HOST_UNREACHABLE    => 4;
use constant REPLY_CONN_REFUSED        => 5;
use constant REPLY_TTL_EXPIRED         => 6;
use constant REPLY_CMD_NOT_SUPPORTED   => 7;
use constant REPLY_ADDR_NOT_SUPPORTED  => 8;

$CODES{REPLY}->[REPLY_SUCCESS] = "Success";
$CODES{REPLY}->[REPLY_GENERAL_FAILURE] = "General failure";
$CODES{REPLY}->[REPLY_CONN_NOT_ALLOWED] = "Not allowed";
$CODES{REPLY}->[REPLY_NETWORK_UNREACHABLE] = "Network unreachable";
$CODES{REPLY}->[REPLY_HOST_UNREACHABLE] = "Host unreachable";
$CODES{REPLY}->[REPLY_CONN_REFUSED] = "Connection refused";
$CODES{REPLY}->[REPLY_TTL_EXPIRED] = "TTL expired";
$CODES{REPLY}->[REPLY_CMD_NOT_SUPPORTED] = "Command not supported";
$CODES{REPLY}->[REPLY_ADDR_NOT_SUPPORTED] = "Address not supported";


#------------------------------------------------------------------------------
# sub new is handled by IO::Socket::INET
#------------------------------------------------------------------------------

###############################################################################
#
# configure - read in the config hash and populate the object.
#
###############################################################################
sub configure
{
    my $self = shift;
    my $args = shift;

    ${*$self}->{SOCKS}->{ProxyAddr} =
        (exists($args->{ProxyAddr}) ?
         delete($args->{ProxyAddr}) :
         croak("You must provide a ProxyAddr to either connect to, or listen on.")
        );

    ${*$self}->{SOCKS}->{ProxyPort} =
        (exists($args->{ProxyPort}) ?
         delete($args->{ProxyPort}) :
         croak("You must provide a ProxyPort to either connect to, or listen on.")
        );

    ${*$self}->{SOCKS}->{ConnectAddr} =
        (exists($args->{ConnectAddr}) ?
         delete($args->{ConnectAddr}) :
         undef
        );

    ${*$self}->{SOCKS}->{ConnectPort} =
        (exists($args->{ConnectPort}) ?
         delete($args->{ConnectPort}) :
         undef
        );
    
    #${*$self}->{SOCKS}->{BindAddr} =
    #    (exists($args->{BindAddr}) ?
    #     delete($args->{BindAddr}) :
    #     undef
    #    );

    #${*$self}->{SOCKS}->{BindPort} =
    #    (exists($args->{BindPort}) ?
    #     delete($args->{BindPort}) :
    #     undef
    #    );

    ${*$self}->{SOCKS}->{AuthType} =
        (exists($args->{AuthType}) ?
         delete($args->{AuthType}) :
         "none"
        );
    
    ${*$self}->{SOCKS}->{RequireAuth} =
        (exists($args->{RequireAuth}) ?
         delete($args->{RequireAuth}) :
         0
        );
    
    ${*$self}->{SOCKS}->{UserAuth} =
        (exists($args->{UserAuth}) ?
         delete($args->{UserAuth}) :
         undef
        );
    
    ${*$self}->{SOCKS}->{Username} =
        (exists($args->{Username}) ?
         delete($args->{Username}) :
         ((${*$self}->{SOCKS}->{AuthType} eq "none") ?
           undef :
           croak("If you set AuthType to userpass, then you must provide a username.")
         )
        );
    
    ${*$self}->{SOCKS}->{Password} =
        (exists($args->{Password}) ?
         delete($args->{Password}) :
         ((${*$self}->{SOCKS}->{AuthType} eq "none") ?
           undef :
           croak("If you set AuthType to userpass, then you must provide a password.")
         )
        );
    
    ${*$self}->{SOCKS}->{Debug} =
        (exists($args->{SocksDebug}) ?
         delete($args->{SocksDebug}) :
         0
        );
    
    ${*$self}->{SOCKS}->{AuthMethods} = [0,0,0];
    ${*$self}->{SOCKS}->{AuthMethods}->[AUTHMECH_ANON] = 1
        unless ${*$self}->{SOCKS}->{RequireAuth};
    #${*$self}->{SOCKS}->{AuthMethods}->[AUTHMECH_GSSAPI] = 1
    #    if (${*$self}->{SOCKS}->{AuthType} eq "gssapi");
    ${*$self}->{SOCKS}->{AuthMethods}->[AUTHMECH_USERPASS] = 1
        if ((!exists($args->{Listen}) &&
            (${*$self}->{SOCKS}->{AuthType} eq "userpass")) ||
            (exists($args->{Listen}) &&
            defined(${*$self}->{SOCKS}->{UserAuth})));
    
    ${*$self}->{SOCKS}->{COMMAND} = undef;

    if (exists($args->{Listen}))
    {
        $args->{LocalAddr} = ${*$self}->{SOCKS}->{ProxyAddr};
        $args->{LocalPort} = ${*$self}->{SOCKS}->{ProxyPort};
        $args->{Reuse} = 1;
    }
    else
    {
        $args->{PeerAddr} = ${*$self}->{SOCKS}->{ProxyAddr};
        $args->{PeerPort} = ${*$self}->{SOCKS}->{ProxyPort};
    }

    $args->{Proto} = "tcp";
    $args->{Type} = SOCK_STREAM;

    my $status = $self->SUPER::configure($args);
    return unless $status;

    #--------------------------------------------------------------------------
    # We are configured... Return the object.
    #--------------------------------------------------------------------------
    return $status;
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Connect Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# connect - On a configure, connect is called to open the connection.  When
#           we do this we have to talk to the SOCKS5 proxy, log in, and
#           connect to the remote host.
#
###############################################################################
sub connect
{
    my $self = shift;

    croak("Undefined IO::Socket::Socks object passed to connect.")
        unless defined($self);

    #--------------------------------------------------------------------------
    # Establish a connection
    #--------------------------------------------------------------------------
    $self = $self->SUPER::connect(@_);

    if (!$self)
    {
        $SOCKS_ERROR = "Connection to proxy failed.";
        return;
    }

    #--------------------------------------------------------------------------
    # Handle any authentication
    #--------------------------------------------------------------------------
    my $auth_mech = $self->_socks5_connect();
    return unless defined $auth_mech;

    if ($auth_mech != AUTHMECH_ANON)
    {
        return unless $self->_socks5_connect_auth();
    }
    
    #--------------------------------------------------------------------------
    # Send the command (CONNECT/BIND/UDP)
    #--------------------------------------------------------------------------
    if (defined(${*$self}->{SOCKS}->{ConnectAddr}) &&
        defined(${*$self}->{SOCKS}->{ConnectPort}))
    {
        return unless $self->_socks5_connect_command(CMD_CONNECT);

        #if (defined(${*$self}->{SOCKS}->{BindPort}))
        #{
        #    ${*$self}->{SOCKS}->{BindAddr} = ${*$self}->{SOCKS}->{ProxyAddr}
        #        unless defined(${*$self}->{SOCKS}->{BindAddr});
        #    return unless $self->_socks5_connect_command(CMD_BIND);
        #}
    }

    return $self;
}


###############################################################################
#
# _socks5_connect - Send the opening handsake, and process the reply.
#
###############################################################################
sub _socks5_connect
{
    my $self = shift;

    #--------------------------------------------------------------------------
    # Send the auth mechanisms
    #--------------------------------------------------------------------------
    my $nmethods = 0;
    my $methods;
    my @methods;
    foreach my $method (0..$#{${*$self}->{SOCKS}->{AuthMethods}})
    {
        if (${*$self}->{SOCKS}->{AuthMethods}->[$method] == 1)
        {
            $methods .= pack('C', $method);
            $nmethods++;
        }
    }
    
    #$self->_debug_connect("Send",\%connect);

    unless( $self->_socks_send( pack('CC', 5, $nmethods) . $methods) )
    {
        $SOCKS_ERROR = 'Timeout';
        return;
    }

    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    my $reply = $self->_socks_read(2);
    unless($reply)
    {
        $SOCKS_ERROR = 'Timeout';
        return;
    }
    
    my ($version, $auth_method) = unpack('CC', split(//, $reply));

    #$self->_debug_connect_reply("Recv",\%connect_reply);
    
    if ($auth_method == AUTHMECH_INVALID)
    {
        $SOCKS_ERROR = $CODES{AUTHMECH}->[$auth_method];
        return;
    }

    return $auth_method;
}


###############################################################################
#
# _socks5_connect_auth - Send and receive a SOCKS5 auth handshake
#
###############################################################################
sub _socks5_connect_auth
{
    my $self = shift;
    
    #--------------------------------------------------------------------------
    # Send the auth
    #--------------------------------------------------------------------------
    unless( $self->_socks_send(pack('CC', 1, length(${*$self}->{SOCKS}->{Username})) . ${*$self}->{SOCKS}->{Username} . pack('C', length(${*$self}->{SOCKS}->{Password})) . length(${*$self}->{SOCKS}->{Password})) )
    {
        $SOCKS_ERROR = 'Timeout';
        return;
    }
    
    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    my $reply = unpack('CC', split(//, $reply));
    my %auth_reply;
    $auth_reply{version} = $self->_socks_read();
    $auth_reply{status} = $self->_socks_read();
    
    $self->_debug_auth_reply("Recv",\%auth_reply);
        
    if ($auth_reply{status} != AUTHREPLY_SUCCESS)
    {
        $SOCKS_ERROR = "Authentication failed with SOCKS5 proxy.";
        return;
    }

    return 1;
}


###############################################################################
#
# _socks_connect_command - Process a SOCKS5 command request
#
###############################################################################
sub _socks5_connect_command
{
    my $self = shift;
    my $command = shift;

    #--------------------------------------------------------------------------
    # Send the command
    #--------------------------------------------------------------------------
    my %command;
    $command{version} = SOCKS5_VER;
    $command{command} = $command;
    $command{reserved} = 0;
    $command{atype} = ADDR_DOMAINNAME;
    $command{host_length} = length(${*$self}->{SOCKS}->{ConnectAddr});
    $command{host} = ${*$self}->{SOCKS}->{ConnectAddr};
    $command{port} = ${*$self}->{SOCKS}->{ConnectPort};

    $self->_debug_command("Send",\%command);
        
    $self->_socks_send($command{version});
    $self->_socks_send($command{command});
    $self->_socks_send($command{reserved});
    $self->_socks_send($command{atype});
    $self->_socks_send($command{host_length});
    $self->_socks_send_raw($command{host});
    $self->_socks_send_raw(pack("n",$command{port}));

    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    my %command_reply;
    $command_reply{version} = $self->_socks_read();
    $command_reply{status} = $self->_socks_read();
    
    if ($command_reply{status} == REPLY_SUCCESS)
    {
        $command_reply{reserved} = $self->_socks_read();
        $command_reply{atype} = $self->_socks_read();

        if ($command_reply{atype} == ADDR_DOMAINNAME)
        {
            $command_reply{host_length} = $self->_socks_read();
            $command_reply{host} = $self->_socks_read_raw($command_reply{host_length});
        }
        elsif ($command_reply{atype} == ADDR_IPV4)
        {
            $command_reply{host} = unpack("N",$self->_socks_read_raw(4));
        }
        
        $command_reply{port} = unpack("n",$self->_socks_read_raw(2));
    }
    
    $self->_debug_command_reply("Recv",\%command_reply);
        
    if ($command_reply{status} != REPLY_SUCCESS)
    {
        $SOCKS_ERROR = $CODES{REPLY}->[$command_reply{status}];
        return;
    }

    return 1;
}
    



###############################################################################
#+-----------------------------------------------------------------------------
#| Accept Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# accept - When we are accepting new connections, we need to do the SOCKS
#          handshaking before we return a usable socket.
#
###############################################################################
sub accept
{
    my $self = shift;

    croak("Undefined IO::Socket::Socks object passed to accept.")
        unless defined($self);

    my $client = $self->SUPER::accept(@_);

    if (!$self)
    {
        $SOCKS_ERROR = "Proxy accept new client failed.";
        return;
    }

    my $authmech = $self->_socks5_accept($client);
    return unless defined($authmech);

    if ($authmech == AUTHMECH_USERPASS)
    {
        return unless $self->_socks5_accept_auth($client);
    }

    return unless $self->_socks5_accept_command($client);

    return $client;
}


###############################################################################
#
# _socks5_accept - Wait for an opening handsake, and reply.
#
###############################################################################
sub _socks5_accept
{
    my $self = shift;
    my $client = shift;

    #--------------------------------------------------------------------------
    # Read the auth mechanisms
    #--------------------------------------------------------------------------
    my %accept;
    $accept{version} = $client->_socks_read();
    $accept{num_methods} = $client->_socks_read();
    $accept{methods} = [];
    foreach (0..($accept{num_methods}-1))
    {
        push(@{$accept{methods}},$client->_socks_read());
    }
    
    $self->_debug_connect("Recv",\%accept);

    if ($accept{num_methods} == 0)
    {
        $SOCKS_ERROR = "No auth methods sent.";
        return;
    }

    my $authmech;
    
    foreach my $method (@{$accept{methods}})
    {
        if (${*$self}->{SOCKS}->{AuthMethods}->[$method] == 1)
        {
            $authmech = $method;
            last;
        }
    }

    if (!defined($authmech))
    {
        $authmech = AUTHMECH_INVALID;
    }

    #--------------------------------------------------------------------------
    # Send the reply
    #--------------------------------------------------------------------------
    my %accept_reply;
    $accept_reply{version} = SOCKS5_VER;
    $accept_reply{auth_method} = AUTHMECH_INVALID;
    $accept_reply{auth_method} = $authmech if defined($authmech);

    $client->_socks_send($accept_reply{version});
    $client->_socks_send($accept_reply{auth_method});
    
    $self->_debug_connect_reply("Send",\%accept_reply);

    if ($authmech == AUTHMECH_INVALID)
    {
        $SOCKS_ERROR = "No available auth methods.";
        return;
    }
    
    return $authmech;
}


###############################################################################
#
# _socks5_accept_auth - Send and receive a SOCKS5 auth handshake
#
###############################################################################
sub _socks5_accept_auth
{
    my $self = shift;
    my $client = shift;
    
    #--------------------------------------------------------------------------
    # Send the auth
    #--------------------------------------------------------------------------
    my %auth;
    $auth{version} = $client->_socks_read();
    $auth{user_length} = $client->_socks_read();
    $auth{user} = $client->_socks_read_raw($auth{user_length});
    $auth{pass_length} = $client->_socks_read();
    $auth{pass} = $client->_socks_read_raw($auth{pass_length});
    
    $self->_debug_auth("Recv",\%auth);
    
    my $status = 0;
    if (defined(${*$self}->{SOCKS}->{UserAuth}))
    {
        $status = &{${*$self}->{SOCKS}->{UserAuth}}($auth{user},$auth{pass});
    }

    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    my %auth_reply;
    $auth_reply{version} = 1;
    $auth_reply{status} = AUTHREPLY_SUCCESS;
    $auth_reply{status} = AUTHREPLY_FAILURE if !$status;
    
    $client->_socks_send($auth_reply{version});
    $client->_socks_send($auth_reply{status});
    
    $self->_debug_auth_reply("Send",\%auth_reply);
        
    if ($auth_reply{status} != AUTHREPLY_SUCCESS)
    {
        $SOCKS_ERROR = "Authentication failed with SOCKS5 proxy.";
        return;
    }

    return 1;
}


###############################################################################
#
# _socks5_acccept_command - Process a SOCKS5 command request.  Since this is
#                           a library and not a server, we cannot process the
#                           command.  Let the parent program handle that.
#
###############################################################################
sub _socks5_accept_command
{
    my $self = shift;
    my $client = shift;

    #--------------------------------------------------------------------------
    # Read the command
    #--------------------------------------------------------------------------
    my %command;
    $command{version} = $client->_socks_read();
    $command{command} = $client->_socks_read();
    $command{reserved} = $client->_socks_read();
    $command{atype} = $client->_socks_read();

    if ($command{atype} == ADDR_DOMAINNAME)
    {
        $command{host_length} =  $client->_socks_read();
        $command{host} = $client->_socks_read_raw($command{host_length});
    }
    elsif ($command{atype} == ADDR_IPV4)
    {
        $command{host} = unpack("N",$client->_socks_read_raw(4));
    }
    else
    {
        $client->_socks_accept_command_reply(REPLY_ADDR_NOT_SUPPORTED);
        $SOCKS_ERROR = $CODES{REPLY}->[REPLY_ADDR_NOT_SUPPORTED];
        return;
    }
    
    $command{port} = unpack("n",$client->_socks_read_raw(2));

    $self->_debug_command("Recv",\%command);

    ${*$client}->{SOCKS}->{COMMAND} = [$command{command},$command{host},$command{port}];

    return 1;
}


###############################################################################
#
# _socks5_acccept_command_reply - Answer a SOCKS5 command request.  Since this
#                                 is a library and not a server, we cannot
#                                 process the command.  Let the parent program
#                                 handle that.
#
###############################################################################
sub _socks5_accept_command_reply
{
    my $self = shift;
    my $reply = shift;
    my $host = shift;
    my $port = shift;

    if (!defined($reply) || !defined($host) || !defined($port))
    {
        croak("You must provide a reply, host, and port on the command reply.");
    }

    #--------------------------------------------------------------------------
    # Send the reply
    #--------------------------------------------------------------------------
    my %command_reply;
    $command_reply{version} = SOCKS5_VER;
    $command_reply{status} = $reply;
    $command_reply{reserved} = 0;
    $command_reply{atype} = ADDR_DOMAINNAME;
    $command_reply{host_length} = length($host);
    $command_reply{host} = $host;
    $command_reply{port} = $port;
    
    $self->_debug_command_reply("Send",\%command_reply);

    $self->_socks_send($command_reply{version});
    $self->_socks_send($command_reply{status});
    $self->_socks_send($command_reply{reserved});
    $self->_socks_send($command_reply{atype});
    $self->_socks_send($command_reply{host_length});
    $self->_socks_send_raw($command_reply{host});
    $self->_socks_send_raw(pack("n",$command_reply{port}));
}


###############################################################################
#
# command - return the command the user request along with the host and
#           port to operate on.
#
###############################################################################
sub command
{
    my $self = shift;

    return ${*$self}->{SOCKS}->{COMMAND};
}


###############################################################################
#
# command_reply - public reply wrapper to the client.
#
###############################################################################
sub command_reply
{
    my $self = shift;
    $self->_socks5_accept_command_reply(@_);
}





###############################################################################
#+-----------------------------------------------------------------------------
#| Helper Functions
#+-----------------------------------------------------------------------------
###############################################################################
sub _socks_send
{
    my $self = shift;
    my $data = shift;
    
    my $blocking = $self->blocking(0) if(${*$self}{io_socket_timeout})
    
    my $selector = IO::Select->new($self);
    my $start = time();
    my $writed = 0;
    my $rc;
    while(!${*$self}{io_socket_timeout} || time() - $start < ${*$self}{io_socket_timeout})
    {
        unless($selector->can_write(1))
        { # socket couldn't accept data for now, check if timeout expired and try again
            next;
        }

        $rc = $self->syswrite($data);
        if($rc > 0)
        { # reduce our message
            $writed += $rc;
            substr($data, 0, $rc) = '';
            if(length($data) == 0)
            { # all data successfully writed
                last;
            }
        }
        elsif($! != EWOULDBLOCK)
        { # some error in the socket; will return false
            last;
        }
    }

    $self->blocking(1) if $blocking;
    
    return $writed;
}

sub _socks_read
{
    my $self = shift;
    my $length = shift || 1;
    
    my $selector = IO::Select->new($self);
    my $start = time();
    my ($buf, $data, $rc);

    while($length > 0 && (!${*$self}{io_socket_timeout} || time() - $start < ${*$self}{io_socket_timeout}))
    {
        unless($selector->can_read(1))
        { # no data in socket for now, check if timeout expired and try again
            next;
        }

        $rc = $socket->sysread($buf, $length);
        if(defined($rc))
        { # no errors
            if($rc > 0)
            { # reduce limit and modify buffer
                $length -= $rc;
                $data .= $buf;
                if($length == 0)
                { # all data successfully readed
                    last;
                }
            }
            else
            { # EOF in the socket
                last;
            }
        }
        elsif($! != EWOULDBLOCK) 
        { # unknown error in the socket
            last;
        }
    }
    
    return $data;
}

###############################################################################
#
# _socks_read - send over the socket after packing according to the rules.
#
###############################################################################
=pod
sub _socks_send
{
    my $self = shift;
    my $data = shift;
    
    $data = pack("C",$data);
    $self->_socks_send_raw($data);
}


###############################################################################
#
# _socks_send_raw - send raw data across the socket.
#
###############################################################################
sub _socks_send_raw
{
    my $self = shift;
    my $data = shift;

    $self->syswrite($data,length($data));
}


###############################################################################
#
# _socks_read - read from the socket, and then unpack according to the rules.
#
###############################################################################
sub _socks_read
{
    my $self = shift;
    my $length = shift;
    $length = 1 unless defined($length);
    
    my $data = $self->_socks_read_raw($length);
    $data = unpack("C",$data);
    return $data;
}


###############################################################################
#
# _socks_read_raw - read raw bytes off of the socket
#
###############################################################################
sub _socks_read_raw
{
    my $self = shift;
    my $length = shift;
    $length = 1 unless defined($length);

    my $data;
    $self->sysread($data,$length);
    return $data;
}
=cut



###############################################################################
#+-----------------------------------------------------------------------------
#| Debug Functions
#+-----------------------------------------------------------------------------
###############################################################################

sub _debug_connect
{
    my $self = shift;
    my $tag = shift;
    my $connect = shift;

    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+-","-"x(4*$connect->{num_methods}),"-+\n";
    print "$tag: | Vers | Auth |";
    if ($connect->{num_methods} > 0)
    {
        print " Meth "," "x(4*($connect->{num_methods}-1)),"|\n";
    }
    print "$tag: +------+------+-","-"x(4*$connect->{num_methods}),"-+\n";

    print "$tag: | ";
    printf("\\%02X",$connect->{version});
    print "  | ";
    printf("\\%02X",$connect->{num_methods});
    print "  | ";
    if ($connect->{num_methods} > 0)
    {
        foreach my $method (@{$connect->{methods}})
        {
            printf("\\%02X ",$method);
        }
        print " |";
    }
    
    print "\n";
    print "$tag: +------+------+-","-"x(4*$connect->{num_methods}),"-+\n";
    print "\n";
}


sub _debug_connect_reply
{
    my $self = shift;
    my $tag = shift;
    my $connect_reply = shift;
    
    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+\n";
    print "$tag: | Vers | Auth |\n";
    print "$tag: +------+------+\n";
    print "$tag: | ";
    
    printf("\\%02X",$connect_reply->{version});
    print "  | ";
    printf("\\%02X",$connect_reply->{auth_method});
    print "  |\n";

    print "$tag: +------+------+\n";
    print "\n";
}


sub _debug_auth
{
    my $self = shift;
    my $tag = shift;
    my $auth = shift;

    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+------","-"x($auth->{user_length}-4),"+------+-----","-"x($auth->{pass_length}-4),"-+\n";
    print "$tag: | Vers | UsrL | User "," "x($auth->{user_length}-4),"| PasL | Pass"," "x($auth->{pass_length}-4)," |\n";
    print "$tag: +------+------+------","-"x($auth->{user_length}-4),"+------+-----","-"x($auth->{pass_length}-4),"-+\n";
    print "$tag: | ";

    printf("\\%02X",$auth->{version});
    print "  | ";
    printf("\\%02d",$auth->{user_length});
    print "  | ";
    print $auth->{user}," "x(4-$auth->{user_length});
    print " | ";
    printf("\\%02d",$auth->{pass_length});
    print "  | ";
    print $auth->{pass}," "x(4-$auth->{pass_length});

    print " |\n";
    print "$tag: +------+------+------","-"x($auth->{user_length}-4),"+------+-----","-"x($auth->{pass_length}-4),"-+\n";
    print "\n";
}  


sub _debug_auth_reply
{
    my $self = shift;
    my $tag = shift;
    my $auth_reply = shift;
    
    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+\n";
    print "$tag: | Vers | Stat |\n";
    print "$tag: +------+------+\n";
    print "$tag: | ";
    
    printf("\\%02X",$auth_reply->{version});
    print "  | ";
    printf("\\%02X",$auth_reply->{status});
    print "  |\n";

    print "$tag: +------+------+\n";
    print "\n";
}


sub _debug_command
{
    my $self = shift;
    my $tag = shift;
    my $command = shift;

    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+------+------+-------","-"x$command->{host_length},"-+-------+\n";
    print "$tag: | Vers | Comm | Resv | ATyp | Host  "," "x$command->{host_length}," | Port  |\n";
    print "$tag: +------+------+------+------+-------","-"x$command->{host_length},"-+-------+\n";
    print "$tag: | "; 

    printf("\\%02X",$command->{version});
    print "  | ";
    printf("\\%02X",$command->{command});
    print "  | ";
    printf("\\%02X",$command->{reserved});
    print "  | ";
    printf("\\%02X",$command->{atype});
    print "  | ";
    printf("\\%02d",$command->{host_length});
    print " - ";
    print $command->{host};
    print " | ";
    printf("%-5d",$command->{port});

    print " |\n";
    print "$tag: +------+------+------+------+-------","-"x$command->{host_length},"-+-------+\n";
    print "\n";
}


sub _debug_command_reply
{
    my $self = shift;
    my $tag = shift;
    my $command_reply = shift;

    return unless ${*$self}->{SOCKS}->{Debug};

    print "$tag: +------+------+";
    print "------+------+-------","-"x$command_reply->{host_length},"-+-------+"
        if ($command_reply->{status} == 0);
    print "\n";

    print "$tag: | Vers | Stat |";
    print " Resv | ATyp | Host  "," "x$command_reply->{host_length}," | Port  |"
        if ($command_reply->{status} == 0);
    print "\n";

    print "$tag: +------+------+";
    print "------+------+-------","-"x$command_reply->{host_length},"-+-------+"
        if ($command_reply->{status} == 0);
    print "\n";
    
    print "$tag: | "; 

    printf("\\%02X",$command_reply->{version});
    print "  | ";
    printf("\\%02X",$command_reply->{status});
    if ($command_reply->{status} == 0)
    {
        print "  | ";
        printf("\\%02X",$command_reply->{reserved});
        print "  | ";
        printf("\\%02X",$command_reply->{atype});
        print "  | ";
        printf("\\%02d",$command_reply->{host_length});
        print " - ";
        print $command_reply->{host};
        print " | ";
        printf("%-5d",$command_reply->{port});
    }
    else
    {
        print " ";
    }
    print " |\n";
    
    print "$tag: +------+------+";
    print "------+------+-------","-"x$command_reply->{host_length},"-+-------+"
        if ($command_reply->{status} == 0);
    print "\n";
    print "\n";
}


1;

__END__

=head1 NAME

IO::Socket::Socks

=head1 SYNOPSIS

Provides a way to open a connection to a SOCKS v5 proxy and use the object
just like an IO::Socket.

=head1 DESCRIPTION

IO::Socket::Socks connects to a SOCKS v5 proxy, tells it to open a
connection to a remote host/port when the object is created.  The
object you receive can be used directly as a socket for sending and
receiving data from the remote host.

=head1 EXAMPLES

=head2 Client

use IO::Socket::Socks;

my $socks = new IO::Socket::Socks(ProxyAddr=>"proxy host",
                                  ProxyPort=>"proxy port",
                                  ConnectAddr=>"remote host",
                                  ConnectPort=>"remote port",
                                 );

print $socks "foo\n";

$socks->close();

=head2 Server

use IO::Socket::Socks;

my $socks_server = new IO::Socket::Socks(ProxyAddr=>"localhost",
                                         ProxyPort=>"8000",
                                         Listen=>1,
                                         UserAuth=>\&auth,
                                         RequireAuth=>1
                                        );

my $select = new IO::Select($socks_server);
        
while(1)
{
    if ($select->can_read())
    {
        my $client = $socks_server->accept();

        if (!defined($client))
        {
            print "ERROR: $SOCKS_ERROR\n";
            next;
        }

        my $command = $client->command();
        if ($command->[0] == 1)  # CONNECT
        {
            # Handle the CONNECT
            $client->command_reply(0, addr, port);
        }
        
        ...
        #read from the client and send to the CONNECT address
        ...

        $client->close();
    }
}
        

sub auth
{
    my $user = shift;
    my $pass = shift;

    return 1 if (($user eq "foo") && ($pass eq "bar"));
    return 0;
}


=head1 METHODS

=head2 new( %cfg )

Creates a new IO::Socket::Socks object.  It takes the following
config hash:

  ProxyAddr => Hostname of the proxy

  ProxyPort => Port of the proxy
  
  ConnectAddr => Hostname of the remote machine

  ConnectPort => Port of the remote machine

  AuthType => What kind of authentication to support:
                none       - no authentication (default)
                userpass  - Username/Password

  RequireAuth => Do not send, or accept, ANON as a valid
                 auth mechanism.

  UserAuth => Function that takes ($user,$pass) and returns
              1 if they are allowed, 0 otherwise.

  Username => If AuthType is set to userpass, then you must
              provide a username.

  Password => If AuthType is set to userpass, then you must
              provide a password.
              
  SocksDebug => This will cause all of the SOCKS traffic to
                be presented on the command line in a form
                similar to the tables in the RFCs.

  Listen => 0 or 1.  Listen on the ProxyAddr and ProxyPort
            for incoming connections.

=head2 accept( )

Accept an incoming connection and return a new IO::Socket::Socks
object that represents that connection.  You must call command()
on this to find out what the incoming connection wants you to do,
and then call command_reply() to send back the reply.

=head2 command( )

After you call accept() the client has sent the command they want
you to process.  This function returns a reference to an array with
the following format:

  [ COMMAND, HOST, PORT ]

=head2 command_reply( REPLY CODE, HOST, PORT )

After you call command() the client needs to be told what the result
is.  The REPLY CODE is as follows (integer value):

  0: Success
  1: General Failure
  2: Connection Not Allowed
  3: Network Unreachable
  4: Host Unreachable
  5: Connection Refused
  6: TTL Expired
  7: Command Not Supported
  8: Address Not Supported

HOST and PORT are the resulting host and port that you use for the
command.

=head1 VARIABLES

=head2 $SOCKS_ERROR

This scalar behaves like $! in that if undef is returned, this variable
should contain a string reason for the error.

=head1 AUTHOR

Ryan Eatmon

=head1 COPYRIGHT

This module is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

#XXX document socks5 rfcs
#XXX document SOCKS_ERROR
