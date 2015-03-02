package Bro::Log::Parse;
# ABSTRACT: Perl interface for parsing Bro logfiles

use strict;
use warnings;
use 5.10.1;

# use Exporter;
use autodie;
use Carp;
use Scalar::Util qw/openhandle/;

our $VERSION = '0.02';

#@EXPORT_OK = qw//;

BEGIN {
  my @accessors = qw/fh file/;

  for my $accessor ( @accessors ) {
    no strict 'refs';
    *$accessor = sub {
      my $self = shift;
      return $self->{$accessor};
    }
  }

}

sub new {
  my $class = shift;
  my $arg = shift;

  my $self = {};

  if ( !defined($arg) ) {
    $self->{diamond} = 1;
  } elsif ( ref($arg) eq 'HASH' ) {
    $self = $arg;
  } elsif ( defined(openhandle($arg)) ) {
    $self->{fh} = $arg;
  } else {
    $self->{file} = $arg;
  }

  bless $self, $class;

  if ( defined($self->{file}) && !(defined($self->{fh})) ) {
    unless ( -f $self->{file} ) {
      croak("Could not open ".$self->{file});
    }

    open( my $fh, "<", $self->{file} )
      or croak("Cannot open ".$self->{file});
    $self->{fh} = $fh;
  }

  if ( !defined($self->{fh}) && ( !defined($self->{diamond}) || !$self->{diamond} ) ) {
    croak("No filename given in constructor. Aborting");
  }

  if ( defined($self->{fh}) ) {
    $self->{names} = [ $self->readheader($self->{fh}) ];
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
