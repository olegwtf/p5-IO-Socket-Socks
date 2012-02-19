#!/usr/bin/env perl

use Test::More;
use IO::Socket::Socks;
use IO::Select;
use Time::HiRes 'time';
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
my $error = int($!); # save it immediately after fail
ok(!defined($sock), 'Socks 5 connect with auth and incorrect password');
ok($error == ESOCKSPROTO, '$! == ESOCKSPROTO') or diag $error, "!=", ESOCKSPROTO;
ok($SOCKS_ERROR == IO::Socket::Socks::AUTHREPLY_FAILURE, '$SOCKS_ERROR == AUTHREPLY_FAILURE')
    or diag int($SOCKS_ERROR), "!=", IO::Socket::Socks::AUTHREPLY_FAILURE;

kill 15, $s_pid;
($s_pid, $s_host, $s_port) = make_socks_server(4, undef, undef, accept => 3, reply => 2);
my $start = time();
$sock = IO::Socket::Socks->new(
	SocksVersion => 4, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port
);
ok(defined($sock), 'Socks 4 blocking connect success');

$start = time();
$sock = IO::Socket::Socks->new(
	SocksVersion => 4, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Blocking => 0
);
ok(defined($sock), 'Socks 4 non-blocking connect success');
my $time_spent = time()-$start;
ok($time_spent < 3, 'Socks 4 non-blocking connect time') or diag "$time_spent sec spent";
my $sel = IO::Select->new($sock);
my $i = 0;
$start = time();
until ($sock->ready) {
	$i++;
	$time_spent = time()-$start;
	ok($time_spent < 1, "Connection attempt $i not blocked") or diag "$time_spent sec spent";
	if ($SOCKS_ERROR == SOCKS_WANT_READ) {
		$sel->can_read(0.8);
	}
	elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
		$sel->can_write(0.8);
	}
	else {
		last;
	}
	$start = time();
}
ok($sock->ready, 'Socks 4 non-blocking socket ready') or diag $SOCKS_ERROR;

kill 15, $s_pid;
($s_pid, $s_host, $s_port) = make_socks_server(5, 'root', 'toor', accept => 3, reply => 2);
$start = time();
$sock = IO::Socket::Socks->new(
	SocksVersion => 5, ProxyAddr => $s_host, ProxyPort => $s_port, ConnectAddr => $h_host, ConnectPort => $h_port, Username => 'root', Password => 'toor',
	AuthType => 'userpass', Blocking => 0
);
ok(defined($sock), 'Socks 5 non-blocking connect success');
$time_spent = time()-$start;
ok($time_spent < 3, 'Socks 5 non-blocking connect time') or diag "$time_spent sec spent";
$sel = IO::Select->new($sock);
$i = 0;
$start = time();
until ($sock->ready) {
	$i++;
	$time_spent = time()-$start;
	ok($time_spent < 1, "Connection attempt $i not blocked") or diag "$time_spent sec spent";
	if ($SOCKS_ERROR == SOCKS_WANT_READ) {
		$sel->can_read(0.8);
	}
	elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
		$sel->can_write(0.8);
	}
	else {
		last;
	}
	$start = time();
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
		$time_spent = time()-$start;
		ok($time_spent < 2, "Connection attempt $i not blocked") or diag "$time_spent sec spent";
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
