#!/usr/bin/env perl

use Test::More;
use IO::Socket::Socks;
use strict;
require 't/subs.pm';

if( $^O eq 'MSWin32' ) {
	plan skip_all => 'Fork and Windows are incompatible';
}

my ($s_pid, $s_host, $s_port) = make_socks_server(4);
my ($h_pid, $h_host, $h_port) = make_http_server();

my $sock = IO::Socket::Socks->new(
	SocksVersion => 4, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port
);
ok(defined($sock), 'Socks 4 connect') or diag $SOCKS_ERROR;

kill 15, $s_pid;
($s_pid, $s_host, $s_port) = make_socks_server(5);
$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port
);
ok(defined($sock), 'Socks 5 connect') or diag $SOCKS_ERROR;

kill 15, $s_pid;
($s_pid, $s_host, $s_port) = make_socks_server(5, 'root', 'toor');
$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Username => 'root', Password => 'toor',
	AuthType => 'userpass'
);
ok(defined($sock), 'Socks 5 connect with auth') or diag $SOCKS_ERROR;

$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Username => 'root', Password => '123',
	AuthType => 'userpass'
);
ok(!defined($sock), 'Socks 5 connect with auth and incorrect password');

kill 15, $s_pid;
kill 15, $h_pid;
done_testing();
