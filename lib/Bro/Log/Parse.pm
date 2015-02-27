package Bro::Log::Parse;

use strict;
use warnings;
use 5.10.1;

use Exporter;
use autodie;
use Carp;

our $VERSION = '0.01';

#@EXPORT_OK = qw//;

sub new {
  my $class = shift;
  my $file = shift;

  my $self = {};
  bless $self, $class;

  if ( defined $file ) {

    unless ( -f $file ) {
      croak("Could not open $file");
    }

    open( my $fh, "<", $file )
      or croak("Cannot open $file");

    $self->{file} = $file;
    $self->{fh} = $fh;

    $self->{names} = [ $self->readheader($fh) ];
  } else {
    $self->{names} = [ $self->readheader() ];
  }

  return $self;
}

sub readheader {
  shift if ( defined $_[0] && ref($_[0]) && UNIVERSAL::can($_[0], 'isa') );

  my $in = shift;

  my @names;
  # first: read header line. This is a little brittle, but... welll... well, it is.
  while ( my $line = defined($in) ? <$in> : <> ) {
    chomp($line);

    my @fields = split /\t/,$line;

    unless ( $line =~ /^#/ ) {
      croak("Did not find fields header: $line");
    }

    if ( "#fields" eq shift(@fields) ) {
      # yay.
      # we have our field names...
      @names = @fields;
      last;
    }
  }

  return @names;
}


sub getLine {
  my $self = shift;

  my $fh = $self->{fh};
  my @names = @{$self->{names}};

  while ( my $line = defined($fh) ? <$fh> : <> ) {
    my $removed = chomp($line);
    next if ( $line =~ /^#/ );

    my @fields = split "\t", $line;
    my %f;

    unless (scalar @names == scalar @fields) {
      next if ( $removed == 0 );
      croak("Number of expected fields does not match number of fields in file");
    }

    for my $name ( @names ) {
      if ( ( $fields[0] eq "-" ) || $fields[0] eq "(empty)" ) {
        shift(@fields); # empty field
      } else {
        $f{$name} = shift(@fields);
      }
    }

    return \%f;
  }
}

1;
