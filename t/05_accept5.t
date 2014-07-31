#!/usr/bin/env perl

use Test::More;
use IO::Socket::Socks;
use IO::Select;
use strict;

my $server = IO::Socket::Socks->new(Listen => 10, Blocking => 0, SocksVersion => 5)
	or die $@;
my $read_select = IO::Select->new($server);
my $serveraddr = $server->sockhost eq '0.0.0.0' ? '127.0.0.1' : $server->sockhost;
my $serverport = $server->sockport;

my %local_clients;
for (1..10) {
	my $client = IO::Socket::Socks->new(Blocking => 0, ProxyAddr => $serveraddr, ProxyPort => $serverport, ConnectAddr => '2gis.com', ConnectPort => 8080);
	ok(defined($client), "Socks 5 client non-blocking connection $_ started");
	$local_clients{$client} = $client;
}

my $accepted = 0;
my $i = 0;
my %server_clients;
while ($accepted != 10 && $i < 30) {
	$i++;
	if ($read_select->can_read(0.5)) {
		my $client = $server->accept();
		$accepted++;
		ok($client, "Socks 5 accept() $accepted") or diag $SOCKS_ERROR;
		if ($client) {
			$client->blocking(0);
			$server_clients{$client} = $client;
		}
	}
}

is(scalar keys %server_clients, 10, "All socks 5 clients accepted");
$read_select->remove($server);
my $write_select = IO::Select->new(values %local_clients);
$i = 0;

while ($write_select->count() && $i<30) {
	$i++;
	if (my @ready = $write_select->can_write(0.5)) {
		for my $client (@ready) {
			$write_select->remove($client);
		}
	}
}

is($write_select->count(), 0, "All clients connected");
$i = 0;

do {
	$i++;
	my @ready;
	if ($read_select->count() || $write_select->count()) {
		if ($read_select->count()) {
			push @ready, $read_select->can_read(0.5);
		}
		
		if ($write_select->count()) {
			push @ready, $write_select->can_write(0.5);
		}
	}
	else {
		@ready = (values %local_clients, values %server_clients);
	}
	
	for my $client (@ready) {
		$read_select->remove($client);
		$write_select->remove($client);
		
		if ($client->ready) {
			if (exists $local_clients{$client}) {
				delete $local_clients{$client};
			}
			else {
				delete $server_clients{$client};
			}
		}
		elsif ($SOCKS_ERROR == SOCKS_WANT_READ) {
			$read_select->add($client);
		}
		elsif ($SOCKS_ERROR == SOCKS_WANT_WRITE) {
			$write_select->add($client);
		}
		else {
			fail("Socks 5 no error"); diag $SOCKS_ERROR;
		}
	}
	
} while (%server_clients && $i < 30);

$server->close();
ok(!%server_clients, "All socks 5 connections accepted properly") or diag((scalar keys %server_clients) . " connections was not completed");

done_testing();
