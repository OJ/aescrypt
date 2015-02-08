#!/usr/bin/perl -w

# aescrypt.pl 0.2.2 by OJ Reeves <oj@buffered.io> @TheColonial
# 					Ported by Lockyc
# Encrypts chats using AES. Inspired by the blowjob.pl script.
# Perl modules required:
#     - Crypt::CBC
#     - Crypt::Rijndael
#     - JSON
#     - MIME::Base64
#     - Digest::SHA
#     - Try::Tiny
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
use Try::Tiny;
use MIME::Base64;
use Digest::SHA qw(sha256_base64);

use HexChat qw(:all);

use vars qw($VERSION %IRSSI $cipher);

$VERSION = "0.2.2";
%IRSSI = (
	authors => 'OJ Reeves',
	contact => 'oj@buffered.io',
	name => 'aescrypt',
	description => 'This script encrypts IRC communications using AES in CBC mode. The script supports per-user and per-channel keys and IVs which can be set via irssi commands. Encrypted content is compresed and Base64 encoded prior to being transmitted.',
	license => 'Apache 2.0',
	url => 'https://github.com/OJ/aescript'
);
HexChat::register($IRSSI{name}, $VERSION, $IRSSI{description});

my $enc_id = 'a';
my $chk_id = 'h';
my $salt_id = 's';
my $required_iv_length = 16;
my $salt_length = 10;

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub get_keys_file {
	return HexChat::get_info('configdir') . '/addons/aescrypt_keys.json';
}

sub load_keys {
	my $source_file = get_keys_file();

	unless (-e $source_file) {
		return {};
	}

	my $json = do {
		local $/ = undef;
		open my $fh, '<', $source_file or die "couldn't open $source_file: $!";
		<$fh>;
	};

	return decode_json($json);
}

sub save_keys {
	my ($keys) = @_;

	my $source_file = get_keys_file();

	open my $fh, '>', $source_file;
	print $fh encode_json($keys);
	close $fh;
}

sub set_iv {
	my ($keys, $server, $id, $iv) = @_;

	unless(exists($keys->{$server})) {
		$keys->{$server} = {};
	}
	unless(exists($keys->{$server}->{$id})) {
		$keys->{$server}->{$id} = {};
	}

	$keys->{$server}->{$id}->{iv} = $iv;
}

sub set_key {
	my ($keys, $server, $id, $key) = @_;

	unless(exists($keys->{$server})) {
		$keys->{$server} = {};
	}
	unless(exists($keys->{$server}->{$id})) {
		$keys->{$server}->{$id} = {};
	}

	$keys->{$server}->{$id}->{key} = $key;
}

sub set_active {
	my ($keys, $server, $id, $active) = @_;

	unless(exists($keys->{$server})) {
		$keys->{$server} = {};
	}
	unless(exists($keys->{$server}->{$id})) {
		$keys->{$server}->{$id} = {};
	}

	$keys->{$server}->{$id}->{active} = $active;
}

sub get_pair {
	my ($keys, $server, $id) = @_;
	if (exists($keys->{$server}) && exists($keys->{$server}->{$id})) {
		return $keys->{$server}->{$id};
	}
	return {};
}

sub get_cipher {
	my ($pair) = @_;
	return Crypt::CBC->new({
		key => $pair->{key},
		iv => $pair->{iv},
		cipher => 'Crypt::Rijndael',
		header => 'none',
		keysize => 32
	});
}

sub encrypt {
	my ($pair, $data) = @_;
	my $cipher = get_cipher($pair);
	my $encrypted = encode_base64($cipher->encrypt($data));
	chomp($encrypted);
	return $encrypted;
}

sub decrypt {
	my ($pair, $data) = @_;
	my $cipher = get_cipher($pair);
	return $cipher->decrypt(decode_base64($data));
}

sub checksum {
	my ($data) = @_;
	return sha256_base64($data);
}

sub create_salt {
	my @set = ('0' .. '9', 'A' .. 'Z', 'a' .. 'z', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '=', '-', '/', '\\');
	return join '' => map $set[rand @set], 1 .. $salt_length;
}

my $keys = load_keys();

sub ui_set_key {
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host")
	};
	my $key = $_[0][1];

	if (length($key) > 0) {
		set_key($keys, $server->{address}, $channel->{name}, $key);
		save_keys($keys);
		HexChat::print("\00315AES Key set to $key");
	} else {
		HexChat::print("\00315AES Key length must be greater than zero");
	}
}

sub ui_set_iv {
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host")
	};
	my $iv = $_[0][1];

	if (length($iv) == $required_iv_length) {
		set_iv($keys, $server->{address}, $channel->{name}, $iv);
		save_keys($keys);
		HexChat::print("\00315AES IV set to $iv");
	} else {
		HexChat::print("\00315AES IV must be $required_iv_length characters long");
	}
}

sub ui_on {
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host")
	};
	set_active($keys, $server->{address}, $channel->{name}, 1);
	save_keys($keys);
	HexChat::print("\00315AES is now active in this window");
}

sub ui_off {
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host"),
		 "nick" => $_[0][0],
		 "tag" => HexChat::get_info("network")
	};
	set_active($keys, $server->{address}, $channel->{name}, 0);
	save_keys($keys);
	HexChat::print("\00315AES is now inactive in this window");
}

sub ui_load {
	$keys = load_keys();
}

sub ui_show {
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host")
	};
	if (exists($keys->{$server->{address}}) && exists($keys->{$server->{address}}->{$channel->{name}})) {
		my $key = $keys->{$server->{address}}->{$channel->{name}}->{key};
		my $iv = $keys->{$server->{address}}->{$channel->{name}}->{iv};
		my $active = $keys->{$server->{address}}->{$channel->{name}}->{active};
		$active = '0' if ($active eq '');

		HexChat::print("\00315Current Key: $key");
		HexChat::print("\00315Current IV : $iv");
		HexChat::print("\00315AES Active : $active");
	} else {
		HexChat::print("\00315No Key or IV set");
	}
}

sub ui_encrypt {
	my ($data, $server, $channel) = @_;

	# Don't transmit blank lines
	unless(length(trim($data)) > 0) {
		return HexChat::EAT_NONE;
	}

	my $pair = get_pair($keys, $server->{address}, $channel->{name});

	unless(exists($pair->{key}) && exists($pair->{iv}) 	&& length($pair->{key}) > 0 && length($pair->{iv}) == $required_iv_length) {
		HexChat::print("\00315AES not configured for this window");
		return HexChat::EAT_NONE;
	}

	# Break messages into chunks of 200 chars each so that we don't end up with
	# message truncation via IRC resulting in borked JSON payloads
	my @chunks = ($data =~ m/.{1,200}/g);

	foreach (@chunks) {
		my $ciphertext = encrypt($pair, create_salt() . $_);
		my $salt = create_salt();
		my $checksum = checksum($_ . $salt);
		my $payload = {$enc_id => $ciphertext, $salt_id => $salt, $chk_id => $checksum};
		my $msg = encode_json($payload);

		HexChat::command("MSG  $channel->{name} $msg");
	}
}

sub msg_received {
	my $json;
	my $event = $_[1];
	my $nick = $_[0][0];
	my $address = HexChat::get_info("host");
	my $channel = {
		"name" => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host"),
		 "nick" => $_[0][0],
		 "tag" => HexChat::get_info("network")
	};

	my $target = $channel->{name};
	my $msg = $_[0][1];

	try {
		$json = decode_json($msg);
	} catch {
		return HexChat::EAT_NONE;
	};

	my $id = $target;
	$id = $nick if $target eq $server->{nick};

	return HexChat::EAT_NONE unless(ref($json) eq "HASH");
	return HexChat::EAT_NONE if(!exists($json->{$enc_id}));

	my $pair = get_pair($keys, $server->{address}, $id);

	return HexChat::EAT_NONE unless(exists($pair->{key}) && exists($pair->{iv}) && length($pair->{key}) > 0 && length($pair->{iv}) == $required_iv_length);

	$msg = substr decrypt($pair, $json->{$enc_id}), $salt_length;
	my $checksum = checksum($msg . $json->{$salt_id});

	if ($checksum eq $json->{$chk_id}) {
		if (length(trim($msg)) > 0) {
			HexChat::emit_print($event, $nick, "\00311{+} $msg");
		} else {
			# ignore blank lines
			return HexChat::EAT_ALL;
		}
	}
}

sub msg_sent {
	my $data = $_[1][0];
	my $channel = {
		name => HexChat::get_info("channel")
	};
	my $server = {
		 "address" => HexChat::get_info("host"),
		 "nick" => $_[0][0],
		 "tag" => HexChat::get_info("network")
	};
	my $pair = get_pair($keys, $server->{address}, $channel->{name});

	if(exists($pair->{key}) && exists($pair->{iv}) && exists($pair->{active}) && $pair->{active} eq 1) {
		ui_encrypt($data, $server, $channel);
		return HexChat::EAT_ALL;
	}
}

sub ui_help {
	HexChat::print("\00303aescrypt script $VERSION commands:");
	HexChat::print("  /aes <msg>     : encrypt a single message");
	HexChat::print("  /aeson         : enable encryption for the current chan");
	HexChat::print("  /aesoff        : disable encryption for the current chan");
	HexChat::print("  /aesiv <iv>    : set the IV for the current chan to <iv>");
	HexChat::print("  /aeskey <key>  : set the Key for the current chan to <key>");
	HexChat::print("  /aesshow       : display the Key and IV for the current chan");
	HexChat::print("  /aesload       : reload the config from disk");
	HexChat::print("  /aeshelp       : show this help information\n");
}

sub ui_banner {
	HexChat::print("\00303aescrypt script $VERSION loaded.");
	HexChat::print("\00303For help run /aeshelp.\n");
}

HexChat::hook_command('aes', 'ui_encrypt');
HexChat::hook_command('aesiv', 'ui_set_iv');
HexChat::hook_command('aeskey', 'ui_set_key');
HexChat::hook_command('aesload', 'ui_load');
HexChat::hook_command('aesshow', 'ui_show');
HexChat::hook_command('aeshelp', 'ui_help');
HexChat::hook_command('aeson', 'ui_on');
HexChat::hook_command('aesoff', 'ui_off');


for ("Private Message", "Private Message to Dialog", "Channel Message", "Your Message") {
	HexChat::hook_print($_, 'msg_received', {data => $_});
}
HexChat::hook_command("", 'msg_sent');

ui_banner();
