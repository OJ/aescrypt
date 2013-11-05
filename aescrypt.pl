#!/usr/bin/perl -w

# aescrypt.pl 0.1.0 by OJ Reeves <oj@buffered.io> @TheColonial
# Encrypts chats using AES. Inspired by the blowjob.pl script.
# Perl modules required:
#     - Crypt::CBC
#     - Crypt::Rijndael
#     - JSON
#     - MIME::Base64
#     - Digest::SHA
# Features:
#     - Per user/channel AES encryption keys and IV
#     - Payloads sent as JSON, with checksum for payload validation
#     - Single messages via /aes <message>
#     - Enable for all messages via /aeson
#     - Disable for all messages via /aesoff
#     - Show configuration via /aesshow
#     - Doesn't screw with bells and other irssi features like the
#       blowjob.pl script does

use strict;

use Crypt::CBC;
use JSON;
use MIME::Base64;
use Digest::SHA qw(sha1_base64);

use Irssi::Irc;
use Irssi;

use vars qw($VERSION %IRSSI $cipher);

$VERSION = "0.1.0";
%IRSSI = (
    authors => 'OJ Reeves',
    contact => 'oj@buffered.io',
    name => 'aescrypt',
    description => 'This script encrypts IRC communications using AES in CBC mode. The script supports per-user and per-channel keys and IVs which can be set via irssi commands. Encrypted content is compresed and Base64 encoded prior to being transmitted.',
    license => 'Apache 2.0',
    url => 'https://github.com/OJ/aescript'
  );

my $enc_id = 'AES';
my $chk_id = 'chk';
my $required_iv_length = 16;

sub get_keys_file
{
  return Irssi::get_irssi_dir() . '/aescrypt_keys.json';
}

sub load_keys
{
  my $source_file = get_keys_file();

  unless (-e $source_file)
  {
    return {};
  }

  my $json = do {
    local $/ = undef;
    open my $fh, '<', $source_file or die "couldn't open $source_file: $!";
    <$fh>;
  };

  return decode_json($json);
}

sub save_keys
{
  my ($keys) = @_;

  my $source_file = get_keys_file();

  open my $fh, '>', $source_file;
  print $fh encode_json($keys);
  close $fh;
}

sub set_iv
{
  my ($keys, $server, $id, $iv) = @_;

  unless(exists($keys->{$server}))
  {
    $keys->{$server} = {};
  }
  unless(exists($keys->{$server}->{$id}))
  {
    $keys->{$server}->{$id} = {};
  }

  $keys->{$server}->{$id}->{iv} = $iv;
}

sub set_key
{
  my ($keys, $server, $id, $key) = @_;

  unless(exists($keys->{$server}))
  {
    $keys->{$server} = {};
  }
  unless(exists($keys->{$server}->{$id}))
  {
    $keys->{$server}->{$id} = {};
  }

  $keys->{$server}->{$id}->{key} = $key;
}

sub set_active
{
  my ($keys, $server, $id, $active) = @_;

  unless(exists($keys->{$server}))
  {
    $keys->{$server} = {};
  }
  unless(exists($keys->{$server}->{$id}))
  {
    $keys->{$server}->{$id} = {};
  }

  $keys->{$server}->{$id}->{active} = $active;
}

sub get_pair
{
  my ($keys, $server, $id) = @_;
  if (exists($keys->{$server}) && exists($keys->{$server}->{$id}))
  {
    return $keys->{$server}->{$id};
  }
  return {};
}

sub get_cipher
{
  my ($pair) = @_;
  return Crypt::CBC->new({
      key => $pair->{key},
      iv => $pair->{iv},
      cipher => 'Crypt::Rijndael',
      header => 'none',
      keysize => 32
    });
}

sub encrypt
{
  my ($pair, $data) = @_;
  my $cipher = get_cipher($pair);
  my $encrypted = encode_base64($cipher->encrypt($data));
  chomp($encrypted);
  return $encrypted;
}

sub decrypt
{
  my ($pair, $data) = @_;
  my $cipher = get_cipher($pair);
  return $cipher->decrypt(decode_base64($data));
}

sub checksum
{
  my ($data) = @_;
  return sha1_base64($data);
}

my $keys = load_keys();

sub ui_set_key
{
  my (undef, $server, $channel) = @_;
  my $key = $_[0];

  if (length($key) > 0)
  {
    set_key($keys, $server->{address}, $channel->{name}, $key);
    save_keys($keys);
    Irssi::active_win()->print("\00315AES Key set to $key");
  } else {
    Irssi::active_win()->print("\00315AES Key length must be greater than zero");
  }
}

sub ui_set_iv
{
  my (undef, $server, $channel) = @_;
  my $iv = $_[0];

  if (length($iv) == $required_iv_length)
  {
    set_iv($keys, $server->{address}, $channel->{name}, $iv);
    save_keys($keys);
    Irssi::active_win()->print("\00315AES IV set to $iv");
  } else {
    Irssi::active_win()->print("\00315AES IV must be $required_iv_length characters long");
  }
}

sub ui_on
{
  my (undef, $server, $channel) = @_;
  set_active($keys, $server->{address}, $channel->{name}, 1);
  save_keys($keys);
  Irssi::active_win()->print("\00315AES is now active in this window");
}

sub ui_off
{
  my (undef, $server, $channel) = @_;
  set_active($keys, $server->{address}, $channel->{name}, 0);
  save_keys($keys);
  Irssi::active_win()->print("\00315AES is now inactive in this window");
}

sub ui_load
{
  $keys = load_keys();
}

sub ui_show
{
  my (undef, $server, $channel) = @_;
  if (exists($keys->{$server->{address}})
    && exists($keys->{$server->{address}}->{$channel->{name}}))
  {
    my $key = $keys->{$server->{address}}->{$channel->{name}}->{key};
    my $iv = $keys->{$server->{address}}->{$channel->{name}}->{iv};
    my $active = $keys->{$server->{address}}->{$channel->{name}}->{active};

    Irssi::active_win()->print("\00315Current Key: $key");
    Irssi::active_win()->print("\00315Current IV : $iv");
    Irssi::active_win()->print("\00315AES Active : $active");
  }
  else
  {
    Irssi::active_win()->print("\00315No Key or IV set");
  }
}

sub ui_encrypt
{
  my ($data, $server, $channel) = @_;
  my $pair = get_pair($keys, $server->{address}, $channel->{name});

  unless(exists($pair->{key}) && exists($pair->{iv})
    && length($pair->{key}) > 0 && length($pair->{iv}) == $required_iv_length)
  {
    Irssi::active_win()->print("\00315AES not configured for this window");
    return;
  }

  my $ciphertext = encrypt($pair, $data);
  my $checksum = checksum($data);
  my $payload = {$enc_id => $ciphertext, $chk_id => $checksum};
  my $msg = encode_json($payload);

  $server->print($channel->{name}, "<$server->{nick}> \00311{+} $data", MSGLEVEL_CLIENTCRAP);
  $server->command("/^msg -$server->{tag} $channel->{name} $msg");
}

sub msg_received
{
  my $json;
  my ($server, $data, $nick, $address) = @_;
  my ($target, $msg) = split(/ :/, $data, 2);

  eval { $json = decode_json($msg); } or return;

  my $id = $target;
  $id = $nick if $target eq $server->{nick};
  
  return if(!exists($json->{$enc_id}));

  my $pair = get_pair($keys, $server->{address}, $id);

  return unless(exists($pair->{key}) && exists($pair->{iv})
    && length($pair->{key}) > 0 && length($pair->{iv}) == $required_iv_length);

  $msg = decrypt($pair, $json->{$enc_id});
  my $checksum = checksum($msg);

  if ($checksum eq $json->{$chk_id})
  {
    Irssi::signal_continue($server, "$target :\00311{+} $msg", $nick, $address);
  }
}

sub msg_sent
{
  my ($data, $server, $channel) = @_;
  my $pair = get_pair($keys, $server->{address}, $channel->{name});

  if(exists($pair->{key}) && exists($pair->{iv}) && exists($pair->{active}) && $pair->{active} eq 1)
  {
    ui_encrypt($data, $server, $channel);
    Irssi::signal_stop();
  }
}

sub ui_help
{
  Irssi::print("\00303aescrypt script $VERSION commands:");
  Irssi::print("  /aes <msg>     : encrypt a single message");
  Irssi::print("  /aeson         : enable encryption for the current chan");
  Irssi::print("  /aesoff        : disable encryption for the current chan");
  Irssi::print("  /aesiv <iv>    : set the IV for the current chan to <iv>");
  Irssi::print("  /aeskey <key>  : set the Key for the current chan to <key>");
  Irssi::print("  /aesshow       : display the Key and IV for the current chan");
  Irssi::print("  /aesload       : reload the config from disk");
  Irssi::print("  /aeshelp       : show this help information\n");
}

sub ui_banner
{
  Irssi::print("\00303aescrypt script $VERSION loaded.");
  Irssi::print("\00303For help run /aeshelp.\n");
}

Irssi::command_bind('aes', 'ui_encrypt');
Irssi::command_bind('aesiv', 'ui_set_iv');
Irssi::command_bind('aeskey', 'ui_set_key');
Irssi::command_bind('aesload', 'ui_load');
Irssi::command_bind('aesshow', 'ui_show');
Irssi::command_bind('aeshelp', 'ui_help');
Irssi::command_bind('aeson', 'ui_on');
Irssi::command_bind('aesoff', 'ui_off');

Irssi::signal_add('event privmsg', 'msg_received');
Irssi::signal_add('send text', 'msg_sent');

ui_banner();
