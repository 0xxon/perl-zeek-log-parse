use 5.10.1;
use strict;
use warnings;

use Test::More tests=>4;

BEGIN { use_ok( 'Bro::Log::Parse' ); }

my $parse = Bro::Log::Parse->new('logs/ssl.log');
my $line = $parse->getLine();
is(scalar keys %$line, 14, "Number of entries");
is($parse->file, 'logs/ssl.log', "File name accessor");
$parse->getLine(); # we do not want the next line
my $fh = $parse->fh;
like(<$fh>, qr/^#close\t2014-08-08-17-13-55/, 'File handle accessor');
