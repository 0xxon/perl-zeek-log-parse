package Bro::Log::Filter::Column;

use strict;
use warnings;
use 5.10.1;

use Carp;

our $VERSION = '0.05';

BEGIN {
  my @accessors = qw/print truncate optional/;

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

  if ( defined($arg) && ref($arg) ne 'HASH' ) {
    croak "Unexpected argument type - requires hashref";
  }

  $arg //= {};

  for my $acc (qw/print truncate optional/) {
    $self->{$acc} = 0;
    $self->{$acc} = $arg->{$acc} if ( defined($arg->{$acc}) );
  }
 
  bless $self, $class; 
}
