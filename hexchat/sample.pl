use vars qw($VERSION);

$VERSION = "0.1.0";

use strict;
#use warnings;
use HexChat qw(:all); # imports all the functions documented on this page

HexChat::register( "User Count", $VERSION, "HexChat::prnt out the number of users on the current channel" );
HexChat::hook_command( "UCOUNT", 'display_count' );

for ("Private Message", "Private Message to Dialog", "Channel Message", "Your Message") {
	HexChat::hook_print($_, 'msg_received', {data => $_});
}
#HexChat::hook_print("Your Message", 'dispose');
HexChat::hook_command("", 'msg_sent');
#HexChat::hook_command("PRIVMSG", 'msg_sent');
#HexChat::hook_command("MSG", 'msg_sent');

sub dispose {
	return HexChat::EAT_HEXCHAT;
}

sub msg_received {
	#HexChat::prnt "Message Received: ";
	# prnt "Current channel: " . HexChat::get_info("channel");
	# prnt "Current server: " . HexChat::get_info("server");
	# prnt "Current host: " . HexChat::get_info("host");
	# prnt "~~~~~~~~~~~~~~~~~";
	# my @userinfo = HexChat::user_info($_[0][0]);
	HexChat::emit_print($_[1], $_[0][0], "DECRYPTED: " . $_[0][1]);
	#HexChat::print($event);
	#HexChat::print(%options);

	# prnt "User_Info account" . $userinfo[0]->{account};
	# prnt "User_Info away" . $userinfo[0]->{away};
	# prnt "User_Info host" . $userinfo[0]->{host};
	# prnt "User_Info lasttalk" . $userinfo[0]->{lasttalk};
	# prnt "User_Info nick" . $userinfo[0]->{nick};
	# prnt "User_Info prefix" . $userinfo[0]->{prefix};
	# prnt "User_Info realname" . $userinfo[0]->{realname};
	# prnt "User_Info selected" . $userinfo[0]->{selected};
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";


	# my $data = HexChat::get_info("channel"). " :" . $_[0][1];
	# my ($target, $msg) = split(/ :/, $data, 2);
	# prnt $data;
	# prnt $target;
	# prnt $msg;

	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";
	# prnt "~~~~~~~~~~~~~~~~~";




	# my $nick = $_[0][0];
	# my $address = $userinfo[0]->{host};
	# my %channel = (
	# 	name => HexChat::get_info("channel")
	# );
	# my $server = {
	# 	 "address" => HexChat::get_info("host"),
	# 	 "nick" => $_[0][0],
	# 	 "tag" => HexChat::get_info("network")
	# };

	# HexChat::prnt "Debug Nick:" . $nick;
	# HexChat::prnt "Debug address:" . $address;
	# HexChat::prnt "Debug server:" . $server;
	# HexChat::prnt "Debug server->address:" . $server->{address};
	# HexChat::prnt "Debug nick:" . $server->{nick};
	# HexChat::prnt "Debug tag:" . $server->{tag};
	return HexChat::EAT_ALL;
}

sub msg_sent {
	prnt "Sent Message:";
	prnt "_[0]: " .$_[0];
	prnt "_[0][0]: " .$_[0][0];
	prnt "_[0][1]: " .$_[0][1];
	prnt "_[0][2]: " .$_[0][2];
	prnt "_[0][3]: " .$_[0][3];
	prnt "_[1]: " .$_[1];
	prnt "_[1][0]: " .$_[1][0];
	prnt "_[1][1]: " .$_[1][1];
	prnt "_[1][2]: " .$_[1][2];
	prnt "_[1][3]: " .$_[1][3];
	# HexChat::emit_print("Your Message", "Lockyc", "~PLUGIN: " . $_[1][0], HexChat::PRI_HIGHEST);
	# HexChat::print()
	HexChat::command("MSG " . HexChat::get_info("channel") . " ENCRYPTED: " . $_[1][0]);
	return HexChat::EAT_ALL;
}

sub get_keys_file {
	return HexChat::get_info('configdir') . '/addons/aescrypt_keys.json';
}

sub display_count {
	HexChat::print HexChat::get_info('configdir') . '/addons/aescrypt_keys.json';
	return HexChat::EAT_HEXCHAT;
}
