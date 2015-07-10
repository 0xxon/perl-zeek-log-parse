package Bro::Log::Hash::App;

use strict;
use warnings;
use 5.10.1;

use Carp;
use Getopt::Long 2.32 qw/GetOptionsFromArray :config bundling auto_version/;
use Digest::SHA1 qw/sha1_hex/;

use Bro::Log::Parse;

our $VERSION = '0.05';

BEGIN {
  my @accessors = qw/key columns/;

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

  bless $self, $class;

  return $self;
}

sub parseArgv {
  my $self = shift;
  my $argv = shift;

  if ( !defined($argv) || ref($argv) ne 'ARRAY' ) {
    croak("cmd needs arrayref as argument");
  }

  my @hash;

  my $res = GetOptionsFromArray($argv,
    "k|key=s" => \$self->{key},
    "p|print=s" => \@hash,
  );
  croak("Error while processing command line arguments") unless ($res);
  @hash = split(/,/,join(',',@hash));
  croak("No columns to hash given") if (scalar @hash == 0);
  $self->{columns} = \@hash;

  croak("No key set") unless defined($self->{key});

  return $argv;
}

sub readLines {
  my $self = shift;
  my $p = shift;
  my %columns = map {$_ => 1} @{$self->columns};

  LINE: while ( my $f = $p->getLine() ) {
    my @outfields;
    for my $field (@{$p->fields}) {
      croak("cannot deal with empty fields yet") if (!defined($f->{$field}));
      my $d = $f->{$field};
      if ( defined($columns{$field}) ) {
        $d = sha1_hex($self->key.$d);
      }
      push (@outfields, $d);
    }
    say join("\t", @outfields);
  }
}

sub cmd {
  my $class = shift;
  my $argv = shift;

  my $self = $class->new();

  $argv = $self->parseArgv($argv);
  # this has to be fixed before we publish this.
  @ARGV = @$argv;

  my $parse = Bro::Log::Parse->new();

  my %fields = map{$_ => 1} @{$parse->fields};
  for my $c (@{$self->columns}) {
    croak("Column $c not in file") unless defined($fields{$c});
  }

  for my $i (@{$parse->headers}) {
    say $i;
  }

  $self->readLines($parse);
}
