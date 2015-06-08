package Mail::SpamAssassin::RedisAddrList;

use strict;
use warnings;

# ABSTRACT: redis address list for spamassassin auto-whitelist
# VERSION

use Mail::SpamAssassin::PersistentAddrList;
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Logger;

use Redis;

our @ISA = qw(Mail::SpamAssassin::PersistentAddrList);

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new(@_);
  $self->{class} = $class;
  bless ($self, $class);
  $self;
}

###########################################################################

sub new_checker {
  my ($factory, $main) = @_;
  my $class = $factory->{class};
  my $conf = $main->{conf};
  my $redis_server = $conf->{auto_whitelist_redis_server};
  my $prefix = $conf->{auto_whitelist_redis_prefix};

  my $self = {
    'main' => $main,
    'redis' => Redis->new(
      server => defined $redis_server ?
        untaint_var($redis_server) : '127.0.0.1:6379',
    ),
    'prefix' => defined $prefix ? $prefix : 'awl_',
  };

  bless ($self, $class);
  return $self;
}

###########################################################################

sub finish {
  my $self = shift;

  $self->{'redis'}->quit;
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr, $signedby) = @_;

  my $entry = {
    addr => $addr,
  };

  my ( $count, $score ) = $self->{'redis'}->mget(
    $self->{'prefix'}.$addr.'_count',
    $self->{'prefix'}.$addr.'_score',
  );
  $entry->{count} =  defined $count ? $count : 0;
  $entry->{totscore} = defined $score ? $score / 1000 : 0;

  dbg("auto-whitelist: redis-based $addr scores ".$entry->{count}.'/'.$entry->{totscore});
  return $entry;
}

sub add_score {
    my($self, $entry, $score) = @_;

    $entry->{count} ||= 0;
    $entry->{addr}  ||= '';

    $entry->{count}++;
    $entry->{totscore} += $score;

    dbg("auto-whitelist: add_score: new count: ".$entry->{count}.", new totscore: ".$entry->{totscore});

    $self->{'redis'}->incr( $self->{'prefix'}.$entry->{'addr'}.'_count' );
    $self->{'redis'}->incrby( $self->{'prefix'}.$entry->{'addr'}.'_score', int($score * 1000) );
    return $entry;
}

sub remove_entry {
  my ($self, $entry) = @_;

  my $addr = $entry->{addr};
  $self->{'redis'}->del(
	  $self->{'prefix'}.$addr.'_count',
	  $self->{'prefix'}.$addr.'_score' );

  if ( my $mailaddr = ($addr) =~ /^(.*)\|ip=none$/) {
    # it doesn't have an IP attached.
    # try to delete any per-IP entries for this addr as well.
    # could be slow...

    $mailaddr =~ s/\*//g;
    my @keys = $self->{'redis'}->keys($self->{'prefix'}.$mailaddr.'*');
    $self->{'redis'}->del( @keys );
  }

  return;
}

1;
