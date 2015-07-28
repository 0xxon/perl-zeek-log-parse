package Bro::Log::Parse;
# ABSTRACT: Perl interface for parsing Bro logfiles

use strict;
use warnings;
use 5.10.1;

# use Exporter;
use autodie;
use Carp;
use Scalar::Util qw/openhandle/;

our $VERSION = '0.06';

#@EXPORT_OK = qw//;

BEGIN {
  my @accessors = qw/fh file line headers fields/;

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
  $self->{line} = undef;

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

  $self->{fields} = $self->{names};

  $self->{empty_as_undef} //= 0;

  return $self;
}

sub readheader {
  my $self = shift;
  my $in = shift;

  my @headerlines;
  my @names;
  # first: read header line. This is a little brittle, but... welll... well, it is.
  while ( my $line = defined($in) ? <$in> : <> ) {
    chomp($line);
    push(@headerlines, $line);

    my @fields = split /\t/,$line;

    unless ( $line =~ /^#/ ) {
      croak("Did not find required fields and types header lines: $line");
    }

    my $type = shift(@fields);
    if ( "#fields" eq  $type ) {
      # yay.
      # we have our field names...
      @names = @fields;
    } elsif ( "#types" eq $type) {
      last;
    }
  }

  $self->{headers} = \@headerlines;

  return @names;
}


sub getLine {
  my $self = shift;

  my $fh = $self->{fh};
  my @names = @{$self->{names}};

  while ( my $line = defined($fh) ? <$fh> : <> ) {
    my $removed = chomp($line);
    $self->{line} = $line;

    my @fields = split "\t", $line;

    if ( $line =~ /^#/  ) {
      if ( "#fields" eq shift(@fields) ) {
        @names = @fields;
        $self->{names} = \@fields;
        # This is not really nice, but for the moment we do not really need any
        # of the other header lines for parsing files - and we do not keep track
        # of them. Sorry...
        $self->{headers} = [ join("\t", ("#fields", @fields)) ];
      }
      next;
    }
    my %f;

    unless (scalar @names == scalar @fields) {
      next if ( $removed == 0 );
      croak("Number of expected fields does not match number of fields in file");
    }

    for my $name ( @names ) {
      my $field = shift(@fields);
      if ( ( $field eq "-" ) ) {
        $f{$name} = undef;
      } elsif ( $field eq "(empty)" ) {
        $f{$name} = $self->{empty_as_undef} ? undef : [];
      } else {
        $f{$name} = $field;
      }
    }

    return \%f;
  }
}

1;
