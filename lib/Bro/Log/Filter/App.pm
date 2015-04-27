package Bro::Log::Filter::App;

use strict;
use warnings;
use 5.10.1;

use Carp;
use Getopt::Long 2.32 qw/GetOptionsFromArray :config bundling auto_version/;

use Bro::Log::Parse;
use Bro::Log::Filter::Column;

use Data::Dumper;

our $VERSION = '0.05';

BEGIN {
  my @accessors = qw/columns unique count ignore null/;

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

  $self->{columns} = {};
  $self->{unique} = 0;
  $self->{count} = 0;
  $self->{ignore} = 0;
  $self->{null} = 0;

  bless $self, $class;

  return $self;
}

sub setColumns {
  my ($self, $option, $value, $columns) = @_;

  my $c = $self->columns;

  for my $i (@$columns) {
    $c->{$i} //= Bro::Log::Filter::Column->new();
    # only allow valid fields
    croak("unknown column option: $option") unless ( exists($c->{$i}->{$option}) );
    $c->{$i}->{$option} = $value;
  }
}

sub parseArgv {
  my $self = shift;
  my $argv = shift;

  if ( !defined($argv) || ref($argv) ne 'ARRAY' ) {
    croak("cmd needs arrayref as argument");
  }

  my @print;
  my @truncate;

  my $res = GetOptionsFromArray($argv,
    "p|print=s" => \@print,
    "t|truncate=s" => \@truncate,
    "u|unique" => \$self->{unique},
    "c|count" => \$self->{count},
    "i|ignore" => \$self->{ignore}, # ignore lines where an element is missing
    "n|null" => \$self->{null}, # show nonexisting elements as null
  );
  croak("Error while processing command line arguments") unless ($res);
  @print = split(/,/,join(',',@print));

  my $pos = 1;
  for my $p ( @print ) {
    $self->setColumns('print', $pos++, [ $p ]);
  }

  for my $t ( @truncate ) {
    $t =~ /(.*)=(\d+)/ || croak("Wrong format for truncate");
    my $field = $1;
    my $num = $2;
    $self->setColumns('truncate', $num, [ $field ]);
  }

  $self->{unique} = 1 if ( $self->count );

  return $argv;
}

sub readLines {
  my $self = shift;
  my $p = shift;

  my %columns = %{$self->columns};

  my %unique;

  LINE: while ( my $f = $p->getLine() ) {
    my @out;
    for my $c (keys %columns) {
      my $column = $columns{$c};
      if ( !exists($f->{$c}) && !$self->{null} ) {
        next LINE if ( $self->ignore );
        croak("Column $c does not exist in file");
      }
      my $field = $f->{$c};
      $field //= '-';

      if ( $column->truncate ) {
        $field = int($field/$column->truncate) * $column->truncate;
      }

      $out[$column->print - 1] = $field if ( $column->print != 0 );
    }
    my $outstr = join("\t", @out);

    if ( $self->unique ) {
      $unique{$outstr}++;
    } else {
      say $outstr;
    }
  }

  if ( $self->unique ) {
    for my $k ( keys %unique ) {
      print $k;
      print "\t".$unique{$k} if $self->count;
      print "\n";
    }
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
  $self->readLines($parse);
}
