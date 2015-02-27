package Bro::Log::Parse;

use strict;
use warnings;
use 5.10.1;

use Exporter;
use autodie;
use Carp;

our $VERSION = '0.01';

#@EXPORT_OK = qw//;

=head1 NAME

Bro::Log::Parse - Object-oriented Perl interface for parsing Bro log files

=head1 SYNOPSIS

  use Bro::Log::Parse;
  
  my $parse = Bro::Log::Parse->new('/path/to/logfile');
  while ( $fields = $parse->getLine() ) {
    print $fields->{ts}."\n";
  }

=head1 ABSTRACT

Perl inerface for parsing Bro logfiles

=head1 DESCRIPTION

This library provides an easy and convenient way to parse the log files generated
by the L<Bro Network Monitoring System|http://www.bro.org>.

=head1 FUNCTIONS

=head2 new(constructor)

The base constructor for Bro::Log::Parse classes. It takes a mandatory parameter containing
the path to the logfile as an adrument and returns the new object. If no file is specified,
input will be read from <>.

If the file pointed to does not exist or cannot be opened, a fatal error is raised.

=cut


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


=head2 getLine()

Read the the line of the input and return the parsed data as a hash. Returns
undef when on EOF.

=cut

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

=head1 AUTHOR
Johanna Amann, E<lt>johanna@icir.orgE<gt>

=head1 COPYRIGHT AND LICENSE
Copyright 2014 by Johanna Amann
This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
