use Test::More tests=>1;

BEGIN{ use_ok( "IO::Socket::Socks" ); }
warn "$IO::Socket::Socks::SOCKET_CLASS used as base class\n";
