package Net::NessusSSL;

use strict;
use vars qw( $prefs %auth );
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Data::Dumper;
use IO::Socket::SSL;
use Config::IniFiles;

use Net::Nessus::Client;
use Net::Nessus::Message;
use vars qw ( $dump );

require Exporter;

@ISA = qw(Exporter IO::Socket::SSL Net::Nessus::Client Net::Nessus::Message  );

@EXPORT = qw(
	
);
$VERSION = '0.01';
$prefs = {};
%auth  = ();

$|=1;

# Preloaded methods go here.


sub new
        {
        my $class = shift;
        my %args = @_;
	my $self = bless {
		_code 		=> 0,
		_error		=> "",
		fast 		=> 1,
		ntp_version	=> '1.2',
		host		=> undef,
		port		=> 1241,
		user		=> undef,
		password	=> undef,
		ssl_version	=> 'TLSv1',
		timeout		=> 1,
		_msg		=> undef,
		_cfg		=> undef,
		_section	=> 'nessus',
		_curr_t		=> undef,
		_holes		=> [],
		_info		=> [],
		preferences	=> {},
		
	},$class;
	if( $args{Cfg} )
                {
                $self->cfg($args{Cfg});
                if( ref($self->cfg) )
                        { $self->init_cfg; }
                else
                        { $self->init_cfg_path; }
                }
        @{$self}{keys %args} = values %args;
        return($self);
        }

sub init_cfg_path
        {
        my $self = shift;
        my $file = $self->cfg;
        my $cfg = new Config::IniFiles( -file => $file, -default => "defaults");
        return($self->set_error(100,"Config file error for $file ($!)")) unless($cfg);
        $self->cfg($cfg);
        $self->ok("Config file $file is ok.");
        $self->init_cfg;
        }

sub init_cfg
        {
        my $self = shift;
        my $cfg = $self->cfg;
	init_section($cfg,$self,$self->section);
	init_section($cfg,$self->{preferences},'preferences');
        }
sub init_section
	{
	my ($cfg,$hash,$section) = @_;
       	if( $cfg->SectionExists( $section ) )
                {
                foreach( $cfg->Parameters($section)  )
                        {
                        $hash->{$_} = $cfg->val($section,$_);
                        }
                }
	}
sub get_buffer
        {
        my $sock = shift;
	my $buf = "";
#	my $buf = <$sock>;
	$buf = $sock->getline;
	chomp($buf);	
	return($buf);
	while( $sock->getline )
		{
		chomp;
		$buf .= $_;
		$sock->flush;
		}
	#$sock->flush;
        return($buf);
        }
sub plugin_set
	{
	my $self = shift;
	my $class = 'preferences';
	my $key = 'plugin_set';
	$self->preference($key,shift) if( @_ );
	return($self->preference($key));
	}
sub preferences
	{
	my $self = shift;
	my $class = 'preferences';
	$self->{$class} = shift if( @_ );
	return($self->{$class});
	}
	
sub preference
        {
        my ($self,$key,$value) = @_;
        my $class = 'preferences';
	return(undef) unless($key);
	$self->{$class}->{$key} = $value if($value);
	return(undef) unless($self->{$class}->{$key});
	return($self->{$class}->{$key});	
	}

sub getlines2
	{
	my $self = shift;
	my $lines = '';
	my $n = 0;
	do 
		{
		my $buf = '';
		$n = $self->ssl->read($buf, 32*1024);
		chomp($buf);
		$buf =~ s/^\s*//g;
		$buf =~ s/\s*$//g;
		$lines .= $buf;
		}
		until( $n == 0 );
	return($lines);
	}
	

sub login
	{
	my $self = shift;
	my $i = 0;
	$self->user(shift) if( @_ );
	$self->password(shift) if( @_ );
	$self->__connect;
	return(0) if( $self->code );
	my $ssl = $self->ssl;
	$ssl->autoflush();
	$ssl->print($self->ntp_fast);
	 my $r = join(' ',$ssl->getline);
	chomp($r);
	if( $r ne $self->ntp_proto )
		{
		$self->set_error(1,"Protocol error $r");
		return(0);
		}
	$ssl->print( $self->user . "\n");
	$ssl->print( $self->password . "\n"); 
	$ssl->print( "CLIENT <|> NESSUS_VERSION  <|> CLIENT\n");
	$r = join(' ',$ssl->getline);
	chomp($r);
	if( $r =~ /Bad login/gis )
		{
		$self->set_error(1,"Bad login ".  $self->user);
		return(0);
		}
	return(1);
	}
	
sub setprefs
	{
	my $self = shift;
	my $p = "CLIENT <|> PREFERENCES <|>\n";
	$self->ssl->flush;
	my $h = $self->preferences;
	foreach( sort keys %$h )
		{ $p .= sprintf("%s <|> %s\n",$_,$h->{$_}); }
	$p .= " <|> CLIENT\n";
        $self->ssl->print($p);
	my $msg = Net::Nessus::Message->new('socket' => $self->ssl,
                                           'sender' => 'SERVER',
                                           'type' => 'PREFERENCES_ERRORS');

	
	}

sub ShowPREFERENCES_ERRORS 
	{
	my ($self,$msg) = @_;
	}

sub ShowHOLE
	{
	my ($self,$msg) = @_;
	my $key = '_holes';
	push(@{$self->{$key}},$msg);
	}
sub ShowINFO
	{
	my ($self,$msg) = @_;
        my $key = '_info';
        push(@{$self->{$key}},$msg);
        }
sub total_holes
	{
	my $self = shift;
	my $key = '_holes';
	my $a = $self->{$key};
	return( scalar @$a);
	}
sub total_info
        {
	my $self = shift;
        my $key = '_info';
	my $a = $self->{$key};
        return(scalar @$a);
        }
sub holes
	{
	my $self = shift;
        my $key = '_holes';
        my $a = $self->{$key};
        return($a);
        }
sub info
        {
        my $self = shift;
        my $key = '_info';
        my $a = $self->{$key};
        return($a);
        }
sub info_list
	{
	my $self = shift;
	return(@{$self->info});
	}
sub hole_list
        {
        my $self = shift;
        return(@{$self->holes});
        }

	
sub attack
	{
	my ($self,$host) = @_;
	$self->setprefs;
	my @hosts = ( $host );
	my $status = $self->Attack(@hosts);
	}

sub getmsg
	{
	my $sock = shift;
	my $buf = "";
	my $t = 2;
	$t = sysread($sock,$buf,4076);
	chomp($buf);
	return($buf);
	}
sub __connect
	{
	my $self = shift;
	# $IO::Socket::SSL::DEBUG = 1;
	my $ssl = IO::Socket::SSL->new(
			PeerAddr 	=> $self->host,
                        PeerPort 	=> $self->port, 
			SSL_version     => $self->ssl_version,
			Timeout 	=> $self->timeout
			)
	or $self->set_error(1,"Can't open connection  [$$] . ($!)");
	$self->ssl($ssl);
	return($self->code);
	}
sub user
        {
        my $this = shift;
        my $key = 'user';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub password
        {
        my $this = shift;
        my $key = 'password';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub host
        {
        my $this = shift;
        my $key = 'host';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub port
        {
        my $this = shift;
        my $key = 'port';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub ssl_version
	{
	my $this = shift;
        my $key = 'ssl_version';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub timeout
	        {
        my $this = shift;
        my $key = 'timeout';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }



sub ntp_fast
	{
	my $this = shift;
	return(sprintf("%s< fast_login >\n",$this->ntp_proto));
	}
sub ntp_version
        {
        my $this = shift;
        my $key = 'ntp_version';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }

sub ntp_proto
        {
        my $this = shift;
	return(sprintf("< NTP/%s >",$this->ntp_version));
        }

sub msg
        {
        my $this = shift;
        my $key = '_msg';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub socket
	{
	my $this = shift;
	return($this->ssl);
	}

sub cfg
        {
        my $this = shift;
        my $key = '_cfg';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }
sub section
        {
        my $this = shift;
        my $key = '_section';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }


sub ssl
	{
	my $this = shift;
        my $key = 'socket';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }

sub ok
	{
	my $self = shift;
	$self->error(shift) if( @_ );
	return($self->code(0));
	}

sub set_error
	{
	my ($self,$code,$msg) = @_;
	$self->error($msg);
	return($self->code($code));
	}


sub code
	{
	my $this = shift;
	my $key = '_code';
	$this->{$key} = shift if( @_ );
	return($this->{$key});
	}
sub error
        {
        my $this = shift;
        my $key = '_error';
        $this->{$key} = shift if( @_ );
        return($this->{$key});
        }


package Net::Nessus::Message::NESSUS_VERSION;
@Net::Nessus::Message::NESSUS_VERSION::ISA = qw(Net::Nessus::Message::SingleLine);


	




1;
__END__

=head1 NAME

Net::NessusSSL - Performs fast login's to launch nessus attacks over SSL.

=head1 SYNOPSIS

  # Using ini file.

  use Net::NessusSSL;
  my $nessus = Net::NessusSSL->new( Cfg => "/opt/local/etc/quickscan.ini"  );

  # Use ini handle
  use Config::IniFiles;
  my $c = "/opt/local/etc/quickscan.ini";
  my $cfg = new Config::IniFiles( -file => $c, -default => "defaults");
  my $nessus = Net::NessusSSL->new(Cfg     => $cfg );

  # Using direct methods no ini.

   my $nessus = Net::NessusSSL->new();
   $nessus->host("nessus.cis-qas.brown.edu");
   $nessus->port(1241);
   $nessus->ntp_version("1.2");
   $nessus->preferences( { host_expansion => 'none', safe_checks => 'yes', checks_read_timeout => 1 });
   $nessus->plugin_set("10835;10861;11808;11921;11790");

  # Now attack something
  

  my $addr = "10.0.0.1";
  if( $nessus->login() )
        {
	$nessus->attack($addr);
        printf("Total info's = %d\n",$nessus->total_info);
        foreach( $nessus->info_list )
                {
                my $info = $_;
                printf("Info:\nID: %s\nPort: %s\nDessc: %s\n",
                        $info->ScanID,
                        $info->Port,
                        $info->Description);
                }
        printf("Total hole's = %d\n",$nessus->total_holes);
        foreach( $nessus->hole_list )
                {
                my $info = $_;
                printf("Info:\nID: %s\nPort: %s\nDessc: %s\n",
                        $info->ScanID,
                        $info->Port,
                        $info->Description);
                }

	}
   else
	{
	die("Nessus login failed %d: %s\n",$nessus->code,$nessus->error);
        }




=head1 DESCRIPTION

This module is really only useful for performing a fast login and attack over ssl.
It depends on IO::Socket::SSL Net::Nessus::Client Net::Nessus::Message for most of the work.

The nessus daemon needs to be running ssl, this version currently doesn't support clear text.
Use Net::Nessus::Client for clear text.

To run ssl uncomment out line "ssl_version = NONE" in nessusd.conf.


=head1 AUTHOR

jpb@brown.edu

=head1 COPYRIGHT

Copyright 2003 Brown University.  All rights reserved.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SEE ALSO

Net::Nessus::Client, Net::Nessus::Messages

=head1 TOO DO

Allow non ssl connections, this is useful for testing.
Allow non fast logins and support plugin and preferences parsing.

Support configuration via .nessusrc, ouch.



=cut
