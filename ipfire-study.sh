

Perl cgi code path for  iptables rules to be saved from web ui and inserted into ipfire host


./html/cgi-bin/firewall.cgi

/srv/web/ipfire/cgi-bin/ovpnmain.cgi:	&General::firewall_reload();
/srv/web/ipfire/cgi-bin/firewall.cgi:	&General::firewall_reload();
/srv/web/ipfire/cgi-bin/vpnmain.cgi:	&General::firewall_reload();

./config/cfgroot/general-functions.pl

sub firewall_reload() {
        &system("/usr/local/bin/firewallctrl");
}

src/misc-progs/firewallctrl.c


int main(int argc, char *argv[]) {
        if (!(initsetuid()))
                exit(1);

        int retval = safe_system("/usr/lib/firewall/rules.pl");

        /* If rules.pl has been successfully executed, the indicator
         * file is removed. */
        if (retval == 0) {
                unlink("/var/ipfire/firewall/reread");
        }

        return 0;
}

./config/firewall/rules.pl
/usr/lib/firewall/rules.pl

cat /var/ipfire/firewall/config

1,REJECT,FORWARDFW,ON,std_net_src,ALL,std_net_tgt,RED,,TCP,,,ON,,,cust_srv,SMTP,Block port 25 (TCP) for outgoing connections to the internet,,,,,,,,,,00:00,00:00,,AUTO,,dnat,,,,,second

2,ACCEPT,FORWARDFW,ON,std_net_src,ALL,tgt_addr,192.168.1.50/32,,TCP,,,ON,,,TGT_PORT,80,,,,,,,,,,,00:00,00:00,ON,AUTO,80,dnat,,,,,second

sub main {
        # Get currently used ipset sets.
        @ipset_used_sets = &ipset_get_sets();

        # Flush all chains.
        &flush();

        # Prepare firewall rules.
        if (! -z  "${General::swroot}/firewall/input"){
                &buildrules(\%configinputfw);
        }
        if (! -z  "${General::swroot}/firewall/outgoing"){
                &buildrules(\%configoutgoingfw);
        }
        if (! -z  "${General::swroot}/firewall/config"){ <------ buildrules to apply the rule
                &buildrules(\%configfwdfw);
        }
}




