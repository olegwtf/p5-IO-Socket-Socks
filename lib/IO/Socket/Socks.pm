##############################################################################
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
#  Copyright (C) 2010 Oleg G
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
our $SOCKS5_RESOLVE = 1;
our $SOCKS4_RESOLVE = 0;

use constant SOCKS5_VER =>  5;
use constant SOCKS4_VER =>  4;

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

# socks5
use constant REPLY_SUCCESS             => 0;
use constant REPLY_GENERAL_FAILURE     => 1;
use constant REPLY_CONN_NOT_ALLOWED    => 2;
use constant REPLY_NETWORK_UNREACHABLE => 3;
use constant REPLY_HOST_UNREACHABLE    => 4;
use constant REPLY_CONN_REFUSED        => 5;
use constant REPLY_TTL_EXPIRED         => 6;
use constant REPLY_CMD_NOT_SUPPORTED   => 7;
use constant REPLY_ADDR_NOT_SUPPORTED  => 8;

$CODES{REPLY}->{&REPLY_SUCCESS} = "Success";
$CODES{REPLY}->{&REPLY_GENERAL_FAILURE} = "General failure";
$CODES{REPLY}->{&REPLY_CONN_NOT_ALLOWED} = "Not allowed";
$CODES{REPLY}->{&REPLY_NETWORK_UNREACHABLE} = "Network unreachable";
$CODES{REPLY}->{&REPLY_HOST_UNREACHABLE} = "Host unreachable";
$CODES{REPLY}->{&REPLY_CONN_REFUSED} = "Connection refused";
$CODES{REPLY}->{&REPLY_TTL_EXPIRED} = "TTL expired";
$CODES{REPLY}->{&REPLY_CMD_NOT_SUPPORTED} = "Command not supported";
$CODES{REPLY}->{&REPLY_ADDR_NOT_SUPPORTED} = "Address not supported";


# socks4
use constant REQUEST_GRANTED         => 90;
use constant REQUEST_FAILED          => 91;
use constant REQUEST_REJECTED_IDENTD => 92;
use constant REQUEST_REJECTED_USERID => 93;

$CODES{REPLY}->{&REQUEST_GRANTED} = "request granted";
$CODES{REPLY}->{&REQUEST_FAILED} = "request rejected or failed";
$CODES{REPLY}->{&REQUEST_REJECTED_IDENTD} = "request rejected becasue SOCKS server cannot connect to identd on the client";
$CODES{REPLY}->{&REQUEST_REJECTED_USERID} = "request rejected because the client program and identd report different user-ids";

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

    ${*$self}->{SOCKS}->{Version} =
        (exists($args->{SocksVersion}) ?
          ($args->{SocksVersion} == 4 || $args->{SocksVersion} == 5 ?
            delete($args->{SocksVersion}) :
            croak("Unsupported socks version specified. Should be 4 or 5")
          ) :
          5
        );
    
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
    # If socks version is 4 it is more easily to establish connection
    #--------------------------------------------------------------------------    
    if(${*$self}->{SOCKS}->{Version} == 4)
    {
        return unless $self->_socks4_connect();
        return $self;
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
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    #--------------------------------------------------------------------------
    # Send the auth mechanisms
    #--------------------------------------------------------------------------
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    # | 1  |    1     | 1 to 255 |
    # +----+----------+----------+
    
    my $nmethods = 0;
    my $methods;
    foreach my $method (0..$#{${*$self}->{SOCKS}->{AuthMethods}})
    {
        if (${*$self}->{SOCKS}->{AuthMethods}->[$method] == 1)
        {
            $methods .= pack('C', $method);
            $nmethods++;
        }
    }
    
    $self->_socks_send(pack('CC', SOCKS5_VER, $nmethods) . $methods)
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => SOCKS5_VER);
        $debug->add(nmethods => $nmethods);
        $debug->add(methods => join('', unpack('C'x$nmethods, $methods)));
        $debug->show('Send: ');
    }

    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    
    my $reply = $self->_socks_read(2)
        or return _timeout();
    
    my ($version, $auth_method) = unpack('CC', $reply);

    if($debug)
    {
        $debug->add(ver => $version);
        $debug->add(method => $auth_method);
        $debug->show('Recv: ');
    }
    
    if ($auth_method == AUTHMECH_INVALID)
    {
        $SOCKS_ERROR = $CODES{AUTHMECH}->[$auth_method];
        return;
    }

    return $auth_method;
}

###############################################################################
#
# _socks5_connect_auth - Send and receive a SOCKS5 auth handshake (rfc1929)
#
###############################################################################
sub _socks5_connect_auth
{
    my $self = shift;
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});
    
    #--------------------------------------------------------------------------
    # Send the auth
    #--------------------------------------------------------------------------
    # +----+------+----------+------+----------+
    # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    # +----+------+----------+------+----------+
    # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    # +----+------+----------+------+----------+
    
    my $uname = ${*$self}->{SOCKS}->{Username};
    my $passwd = ${*$self}->{SOCKS}->{Password};
    my $ulen = length($uname);
    my $plen = length($passwd);
    $self->_socks_send(pack('CC', 1, $ulen) . $uname . pack('C', $plen) . $passwd)
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => 1);
        $debug->add(ulen => $ulen);
        $debug->add(uname => $uname);
        $debug->add(plen => $plen);
        $debug->add(passwd => $passwd);
        $debug->show('Send: ');
    }
    
    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    # +----+--------+
    # |VER | STATUS |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    
    my $reply = $self->_socks_read(2)
        or return _timeout();

    my ($ver, $status) = unpack('CC', $reply);

    if($debug)
    {
        $debug->add(ver => $ver);
        $debug->add(status => $status);
        $debug->show('Recv: ');
    }

    if ($status != AUTHREPLY_SUCCESS)
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
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    #--------------------------------------------------------------------------
    # Send the command
    #--------------------------------------------------------------------------
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    
    my $atyp = $SOCKS5_RESOLVE ? ADDR_DOMAINNAME : ADDR_IPV4;
    my $dstaddr = $SOCKS5_RESOLVE ? ${*$self}->{SOCKS}->{ConnectAddr} : inet_aton(${*$self}->{SOCKS}->{ConnectAddr});
    my $hlen = length($dstaddr) if $SOCKS5_RESOLVE;
    my $dstport = pack('n', ${*$self}->{SOCKS}->{ConnectPort});
    $self->_socks_send(pack('CCCC', SOCKS5_VER, $command, 0, $atyp) . (defined($hlen) ? pack('C', $hlen) : '') . $dstaddr . $dstport)
        or return _timeout();

    if($debug)
    {
        $debug->add(ver => SOCKS5_VER);
        $debug->add(cmd => $command);
        $debug->add(rsv => 0);
        $debug->add(atyp => $atyp);
        $debug->add(hlen => $hlen) if defined $hlen;
        $debug->add(dstaddr => $SOCKS5_RESOLVE ? $dstaddr : inet_ntoa($dstaddr));
        $debug->add(dstport => ${*$self}->{SOCKS}->{ConnectPort});
        $debug->show('Send: ');
    }

    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    
    my $reply = $self->_socks_read(4)
        or return _timeout();
    
    my ($ver, $rep, $rsv);
    ($ver, $rep, $rsv, $atyp) = unpack('CCCC', $reply);
    
    if($debug)
    {
        $debug->add(ver => $ver);
        $debug->add(rep => $rep);
        $debug->add(rsv => $rsv);
        $debug->add(atyp => $atyp);
    }
    
    if ($atyp == ADDR_DOMAINNAME)
    {
        $reply = $self->_socks_read()
            or return _timeout();
        
        my $hlen = unpack('C', $reply);
        my $bndaddr = $self->_socks_read($hlen)
            or return _timeout();
        
        if($debug)
        {
            $debug->add(hlen => $hlen);
            $debug->add(bndaddr => $bndaddr);
        }
    }
    elsif ($atyp == ADDR_IPV4)
    {
        $reply = $self->_socks_read(4)
            or return _timeout();
        
        if($debug)
        {
            my $bndaddr = inet_ntoa($reply);
            $debug->add(bndaddr => $bndaddr);
        }
    }
    else
    {
        $SOCKS_ERROR = 'Socks server returns unsupported address type';
        return;
    }
    
    $reply = $self->_socks_read(2)
        or return _timeout();
    
    if($debug)
    {
        my $bndport = unpack('n', $reply);
        $debug->add(bndport => $bndport);
        $debug->show('Recv: ');
    }
   
    if($rep != REPLY_SUCCESS)
    {
        $SOCKS_ERROR = $CODES{REPLY}->{$rep};
        return;
    }

    return 1;
}

###############################################################################
#
# _socks4_connect - Send the opening handsake, and process the reply.
#
###############################################################################
sub _socks4_connect
{
    # http://ss5.sourceforge.net/socks4.protocol.txt
    # http://ss5.sourceforge.net/socks4A.protocol.txt
    
    my $self = shift;
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});
    
    #--------------------------------------------------------------------------
    # Send the command
    #--------------------------------------------------------------------------
    # +-----+-----+----------+---------------+----------+------+   
    # | VER | CMD | DST.PORT |   DST.ADDR    |  USERID  | NULL |
    # +-----+-----+----------+---------------+----------+------+
    # |  1  |  1  |    2     |       4       | variable |  1   |
    # +-----+-----+----------+---------------+----------+------+
    
    my $cmd = 1;
    my $dstaddr = $SOCKS4_RESOLVE ? inet_aton('0.0.0.1') : inet_aton(${*$self}->{SOCKS}->{ConnectAddr});
    my $dstport = pack('n', ${*$self}->{SOCKS}->{ConnectPort});
    my $userid  = ${*$self}->{SOCKS}->{Username};
    my $dsthost;
    if($SOCKS4_RESOLVE)
    { # socks4a
        $dsthost = ${*$self}->{SOCKS}->{ConnectAddr} . pack('C', 0);
    }
    
    $self->_socks_send(pack('CC', SOCKS4_VER, $cmd) . $dstport . $dstaddr . $userid . pack('C', 0) . $dsthost)
        or return _timeout();
        
    if($debug)
    {
        $debug->add(ver => SOCKS4_VER);
        $debug->add(cmd => $cmd);
        $debug->add(dstport => ${*$self}->{SOCKS}->{ConnectPort});
        $debug->add(dstaddr => inet_ntoa($dstaddr));
        $debug->add(userid => $userid);
        $debug->add(null => 0);
        if($dsthost)
        {
            $debug->add(dsthost => ${*$self}->{SOCKS}->{ConnectAddr});
            $debug->add(null => 0);
        }
        $debug->show('Send: ');
    }
    
    #--------------------------------------------------------------------------
    # Read the reply
    #--------------------------------------------------------------------------
    # +-----+-----+----------+---------------+
    # | VER | REP | BND.PORT |   BND.ADDR    |
    # +-----+-----+----------+---------------+
    # |  1  |  1  |    2     |       4       |
    # +-----+-----+----------+---------------+
    
    my $reply = $self->_socks_read(8)
        or return _timeout();
    
    my ($ver, $rep, $bndport) = unpack('CCn', $reply);
    if($debug)
    {
        my $bndaddr = inet_ntoa(substr($reply, 4));
        
        $debug->add(ver => $ver);
        $debug->add(rep => $rep);
        $debug->add(bndport => $bndport);
        $debug->add(bndaddr => $bndaddr);
        $debug->show('Recv: ');
    }
    
    if($rep != REQUEST_GRANTED)
    {
        $SOCKS_ERROR = $CODES{REPLY}->{$rep};
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

    if (!$client)
    {
        $SOCKS_ERROR = "Proxy accept new client failed.";
        return;
    }
    
    if(${*$self}->{SOCKS}->{Version} == 4)
    {
        return unless $self->_socks4_accept($client);
    }
    else
    {
        my $authmech = $self->_socks5_accept($client);
        return unless defined($authmech);

        if ($authmech == AUTHMECH_USERPASS)
        {
            return unless $self->_socks5_accept_auth($client);
        }

        return unless $self->_socks5_accept_command($client);
    }

    # inherit debug level for new socket
    ${*$client}->{SOCKS}->{Debug} = ${*$self}->{SOCKS}->{Debug};
    
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
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    #--------------------------------------------------------------------------
    # Read the auth mechanisms
    #--------------------------------------------------------------------------
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    # | 1  |    1     | 1 to 255 |
    # +----+----------+----------+
    
    my $request = $client->_socks_read(2)
        or return _timeout();
    
    my ($ver, $nmethods) = unpack('CC', $request);
    $request = $client->_socks_read($nmethods)
        or return _timeout();
    
    my @methods = unpack('C'x$nmethods, $request);
    
    if($debug)
    {
        $debug->add(ver => $ver);
        $debug->add(nmethods => $nmethods);
        $debug->add(methods => join('', @methods));
        $debug->show('Recv: ');
    }
    
    if($ver != SOCKS5_VER)
    {
        $SOCKS_ERROR = "Socks version should be 5, $ver recieved";
        return;
    }
    
    if ($nmethods == 0)
    {
        $SOCKS_ERROR = "No auth methods sent.";
        return;
    }

    my $authmech;
    
    foreach my $method (@methods)
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
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    
    $client->_socks_send(pack('CC', SOCKS5_VER, $authmech))
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => SOCKS5_VER);
        $debug->add(method => $authmech);
        $debug->show('Send: ');
    }

    if ($authmech == AUTHMECH_INVALID)
    {
        $SOCKS_ERROR = "No available auth methods.";
        return;
    }
    
    return $authmech;
}


###############################################################################
#
# _socks5_accept_auth - Send and receive a SOCKS5 auth handshake (rfc1929)
#
###############################################################################
sub _socks5_accept_auth
{
    my $self = shift;
    my $client = shift;
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});
    
    #--------------------------------------------------------------------------
    # Read the auth
    #--------------------------------------------------------------------------
    # +----+------+----------+------+----------+
    # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    # +----+------+----------+------+----------+
    # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    # +----+------+----------+------+----------+
    
    my $request = $client->_socks_read(2)
        or return _timeout();
    
    my ($ver, $ulen) = unpack('CC', $request);
    $request = $client->_socks_read($ulen+1)
        or return _timeout();
    
    my $uname = substr($request, 0, $ulen);
    my $plen = unpack('C', substr($request, $ulen));
    my $passwd = $client->_socks_read($plen)
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => $ver);
        $debug->add(ulen => $ulen);
        $debug->add(uname => $uname);
        $debug->add(plen => $plen);
        $debug->add(passwd => $passwd);
        $debug->show('Recv: ');
    }
    
    my $status;
    if (defined(${*$self}->{SOCKS}->{UserAuth}))
    {
        $status = &{${*$self}->{SOCKS}->{UserAuth}}($uname, $passwd);
    }

    #--------------------------------------------------------------------------
    # Send the reply
    #--------------------------------------------------------------------------
    # +----+--------+
    # |VER | STATUS |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    
    $status = $status ? AUTHREPLY_SUCCESS : AUTHREPLY_FAILURE;
    $client->_socks_send(pack('CC', 1, $status))
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => 1);
        $debug->add(status => $status);
        $debug->show('Send: ');
    }
    
    if ($status != AUTHREPLY_SUCCESS)
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
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    #--------------------------------------------------------------------------
    # Read the command
    #--------------------------------------------------------------------------
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    
    my $request = $client->_socks_read(4)
        or return _timeout();
    
    my ($ver, $cmd, $rsv, $atyp) = unpack('CCCC', $request);
    if($debug)
    {
        $debug->add(ver => $ver);
        $debug->add(cmd => $cmd);
        $debug->add(rsv => $rsv);
        $debug->add(atyp => $atyp);
    }

    my $dstaddr;
    if ($atyp == ADDR_DOMAINNAME)
    {
        $request = $client->_socks_read()
            or return _timeout();
        
        my $hlen = unpack('C', $request);
        $dstaddr = $client->_socks_read($hlen)
            or return _timeout();
        
        if($debug)
        {
            $debug->add(hlen => $hlen);
        }
    }
    elsif ($atyp == ADDR_IPV4)
    {
        $request = $client->_socks_read(4)
            or return _timeout();
        
        $dstaddr = inet_ntoa($request);
    }
    else
    {
        $client->_socks5_accept_command_reply(REPLY_ADDR_NOT_SUPPORTED, '1.1.1.1', 1);
        $SOCKS_ERROR = $CODES{REPLY}->{REPLY_ADDR_NOT_SUPPORTED};
        return;
    }
    
    $request = $client->_socks_read(2)
        or return _timeout();
    
    my $dstport = unpack('n', $request);
    
    if($debug)
    {
        $debug->add(dstaddr => $dstaddr);
        $debug->add(dstport => $dstport);
        $debug->show('Recv: ');
    }

    ${*$client}->{SOCKS}->{COMMAND} = [$cmd, $dstaddr, $dstport];

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
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    if (!defined($reply) || !defined($host) || !defined($port))
    {
        croak("You must provide a reply, host, and port on the command reply.");
    }

    #--------------------------------------------------------------------------
    # Send the reply
    #--------------------------------------------------------------------------
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    
    my $atyp = $SOCKS5_RESOLVE ? ADDR_DOMAINNAME : ADDR_IPV4;
    my $bndaddr = $SOCKS5_RESOLVE ? $host : inet_aton($host);
    my $hlen = length($bndaddr) if $SOCKS5_RESOLVE;
    $self->_socks_send(pack('CCCC', SOCKS5_VER, $reply, 0, $atyp) . ($SOCKS5_RESOLVE ? pack('C', $hlen) : '') . $bndaddr . pack('n', $port))
        or return _timeout();
    
    if($debug)
    {
        $debug->add(ver => SOCKS5_VER);
        $debug->add(rep => $reply);
        $debug->add(rsv => 0);
        $debug->add(atyp => $atyp);
        $debug->add(hlen => $hlen) if $SOCKS5_RESOLVE;
        $debug->add(bndaddr => $SOCKS5_RESOLVE ? $bndaddr : inet_ntoa($bndaddr));
        $debug->add(bndport => $port);
        $debug->show('Send: ');
    }
}


###############################################################################
#
# _socks4_accept - Wait for an opening handsake, and reply.
#
###############################################################################
sub _socks4_accept
{
    my $self = shift;
    my $client = shift;
    my $debug = IO::Socket::Socks::Debug->new() if(${*$self}->{SOCKS}->{Debug});

    #--------------------------------------------------------------------------
    # Read the auth mechanisms
    #--------------------------------------------------------------------------
    # +-----+-----+----------+---------------+----------+------+   
    # | VER | CMD | DST.PORT |   DST.ADDR    |  USERID  | NULL |
    # +-----+-----+----------+---------------+----------+------+
    # |  1  |  1  |    2     |       4       | variable |  1   |
    # +-----+-----+----------+---------------+----------+------+        
    
    my $request = $client->_socks_read(8)
        or return _timeout();
    
    my ($ver, $cmd, $dstport) = unpack('CCn', $request);
    my $dstaddr = inet_ntoa( substr($request, 4) );
    
    my $userid = '';
    my $c;
    
    while(1)
    {
        $c = $client->_socks_read()
            or return _timeout(); # c == 0 ????
    }
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
    
    my $blocking = $self->blocking(0) if(${*$self}{io_socket_timeout});
    
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

        $rc = $self->sysread($buf, $length);
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

sub _timeout
{
    $SOCKS_ERROR = 'Timeout';
    undef;
}


###############################################################################
#+-----------------------------------------------------------------------------
#| Helper Package to display pretty debug messages
#+-----------------------------------------------------------------------------
###############################################################################

package IO::Socket::Socks::Debug;

sub new
{
    my ($class) = @_;
    
    my $self = {};
    $self->{data} = [];
    
    bless $self, $class;
}

sub add
{
    my ($self, $name, $value) = @_;
    push @{$self->{data}}, $name, $value;
}

sub show
{
    my ($self, $tag) = @_;
    
    _separator($self->{data}, $tag);
    _row($self->{data}, 0, $tag);
    _separator($self->{data}, $tag);
    _row($self->{data}, 1, $tag);
    _separator($self->{data}, $tag);
    
    print "\n";
    
    @{$self->{data}} = ();
}

sub _separator
{
    my $ref = shift;
    my $tag = shift;
    my ($row1_len, $row2_len, $len);
    
    print $tag, '+';
    
    for(my $i=0; $i<@$ref; $i+=2)
    {
        $row1_len = length($ref->[$i]);
        $row2_len = length($ref->[$i+1]);
        $len = ($row1_len > $row2_len ? $row1_len : $row2_len)+2;
        
        print '-' x $len, '+';
    }
    
    print "\n";
}

sub _row
{
    my $ref = shift;
    my $row = shift;
    my $tag = shift;
    my ($row1_len, $row2_len, $len);
    
    print $tag, '|';
    
    for(my $i=0; $i<@$ref; $i+=2)
    {
        $row1_len = length($ref->[$i]);
        $row2_len = length($ref->[$i+1]);
        $len = ($row1_len > $row2_len ? $row1_len : $row2_len);
        
        printf(' %-'.$len.'s |', $ref->[$i+$row]);
    }
    
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
receiving data from the remote host. In addition to create socks client
this module could be used to create socks server. See examples below.

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
            
  Timeout => Timeout openning new socks socket

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
should contain a string reason for the error. Imported by default.

=head2 $SOCKS5_RESOLVE

If this variable have true value resolving of host names will be done
by proxy server, otherwise resolving will be done locally. Note: some
bugous socks5 servers doesn't support resolving of host names. Default
value is true. This variable is not importable.

=head1 AUTHOR

Ryan Eatmon

=head1 COPYRIGHT

This module is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

#XXX document socks5 rfcs
#XXX document SOCKS_ERROR
