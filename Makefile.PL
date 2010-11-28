use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'      => 'IO::Socket::Socks',
    'PREREQ_PM' => { 'IO::Socket::INET'  => 0, 'IO::Select' => 0 },
    'VERSION_FROM'  => 'lib/IO/Socket/Socks.pm',
    'dist' => {
        'COMPRESS' => 'gzip --best'
    }
);
