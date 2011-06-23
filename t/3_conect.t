#!/usr/bin/env perl

use Test::More;
use IO::Socket::Socks;
use IO::Select;
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
($s_pid, $s_host, $s_port) = make_socks_server(4, undef, undef, accept => 3, reply => 2);
my $start = time();
$sock = IO::Socket::Socks->new(
	SocksVersion => 4, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port
);
ok(defined($sock), 'Socks 4 blocking connect success');
ok(time()-$start >= 5, 'Socks 4 blocking connect time');

$start = time();
$sock = IO::Socket::Socks->new(
	SocksVersion => 4, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Blocking => 0
);
ok(defined($sock), 'Socks 4 non-blocking connect success');
ok(time()-$start < 3, 'Socks 4 non-blocking connect time');
my $sel = IO::Select->new($sock);
my $i = 0;
$start = time();
until ($sock->ready) {
	$i++;
	ok(time()-$start < 2, "Connection attempt $i not blocked");
	$start = time();
	if ($SOCKS_ERROR == SOCKS_WANT_READ) {
		$sel->can_read(0.8);
	}
	elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
		$sel->can_write(0.8);
	}
	else {
		last;
	}
}
ok($sock->ready, 'Socks 4 non-blocking socket ready') or diag $SOCKS_ERROR;

kill 15, $s_pid;
($s_pid, $s_host, $s_port) = make_socks_server(5, 'root', 'toor', accept => 3, reply => 2);
$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Username => 'root', Password => 'toor',
	AuthType => 'userpass', Blocking => 0
);
ok(defined($sock), 'Socks 5 non-blocking connect success');
ok(time()-$start < 3, 'Socks 5 non-blocking connect time');
$sel = IO::Select->new($sock);
$i = 0;
$start = time();
until ($sock->ready) {
	$i++;
	ok(time()-$start < 2, "Connection attempt $i not blocked");
	$start = time();
	if ($SOCKS_ERROR == SOCKS_WANT_READ) {
		$sel->can_read(0.8);
	}
	elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
		$sel->can_write(0.8);
	}
	else {
		last;
	}
}
ok($sock->ready, 'Socks 5 non-blocking socket ready') or diag $SOCKS_ERROR;

$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Username => 'root', Password => 'toot',
	AuthType => 'userpass', Blocking => 0
);
if (defined $sock) {
	$sel = IO::Select->new($sock);
	$i = 0;
	$start = time();
	until ($sock->ready) {
		$i++;
		ok(time()-$start < 2, "Connection attempt $i not blocked");
		$start = time();
		if ($SOCKS_ERROR == SOCKS_WANT_READ) {
			$sel->can_read(0.8);
		}
		elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
			$sel->can_write(0.8);
		}
		else {
			last;
		}
	}
	
	ok(!$sock->ready, 'Socks 5 non-blocking connect with fail auth');
}
else {
	pass('Socks 5 non-blocking connect with fail auth (immediatly)');
}

kill 15, $s_pid;
kill 15, $h_pid;
done_testing();
