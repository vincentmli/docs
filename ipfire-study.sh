

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

GUI menu

config/cfgroot/header.pl
/var/ipfire/header.pl

lfs/configroot
log/configroot:#var/ipfire/menu.d
log/configroot:var/ipfire/menu.d/00-menu.main
log/configroot:var/ipfire/menu.d/10-system.menu
log/configroot:var/ipfire/menu.d/20-status.menu
log/configroot:var/ipfire/menu.d/30-network.menu
log/configroot:var/ipfire/menu.d/40-services.menu
log/configroot:var/ipfire/menu.d/50-firewall.menu
log/configroot:var/ipfire/menu.d/60-ipfire.menu
log/configroot:var/ipfire/menu.d/70-log.menu
log/configroot:#var/ipfire/menu.d/EX-apcupsd.menu
log/configroot:#var/ipfire/menu.d/EX-guardian.menu
log/configroot:#var/ipfire/menu.d/EX-mpfire.menu
log/configroot:#var/ipfire/menu.d/EX-samba.menu
log/configroot:#var/ipfire/menu.d/EX-tor.menu
log/configroot:#var/ipfire/menu.d/EX-wio.menu
log/configroot:#var/ipfire/menu.d/EX-wlanap.menu

firewall.cgi javascript to control NAT visibility

                // Show/Hide elements when NAT checkbox is checked.
                if (\$("#USE_NAT").attr("checked")) {
                        \$("#actions").hide();
                } else {
                        \$(".NAT").hide();
                }

                // Show NAT area when "use nat" checkbox is clicked
                \$("#USE_NAT").change(function() {
                        \$(".NAT").toggle(); <====div class "NAT"
                        \$("#actions").toggle(); <====table id actions
                });

                // Hide SNAT items when DNAT is selected and vice versa.
                if (\$('input[name=nat]:checked').val() == 'dnat') { <===input name nat
                        \$('.snat').hide(); <=====class snat
                } else {
                        \$('.dnat').hide(); <====class dnat
                }

                // Show/Hide elements when SNAT/DNAT get changed.
                \$('input[name=nat]').change(function() {
                        \$('.snat').toggle();
                        \$('.dnat').toggle();
                });


                print <<END;
                        <center>
                                <table width="80%" class='tbl' id='actions'> <====== table id 'actions'
                                        <tr>
                                                <td width="33%" align="center" bgcolor="$color{'color17'}">
                                                        &nbsp;<br>&nbsp;
                                                </td>
                                                <td width="33%" align="center" bgcolor="$color{'color25'}">
                                                        &nbsp;<br>&nbsp;
                                                </td>
                                                <td width="33%" align="center" bgcolor="$color{'color16'}">
                                                        &nbsp;<br>&nbsp;
                                                </td>
                                        </tr>
                                        <tr>
                                                <td width="33%" align="center">
                                                        <label>
                                                                <input type="radio" name="RULE_ACTION" value="ACCEPT" $checked{"RULE_ACTION"}{"ACCEPT"}>
                                                                <strong>$Lang::tr{'fwdfw ACCEPT'}</strong>
                                                        </label>
                                                </td>
                                                <td width="33%" align="center">
                                                        <label>
                                                                <input type="radio" name="RULE_ACTION" value="DROP" $checked{"RULE_ACTION"}{"DROP"}>
                                                                <strong>$Lang::tr{'fwdfw DROP'}</strong>
                                                        </label>
                                                </td>
                                                <td width="33%" align="center">
                                                        <label>
                                                                <input type="radio" name="RULE_ACTION" value="REJECT" $checked{"RULE_ACTION"}{"REJECT"}>
                                                                <strong>$Lang::tr{'fwdfw REJECT'}</strong>
                                                        </label>
                                                </td>
                                        </tr>
                                </table>
                        </center>

                        <br>
END



                #---SNAT / DNAT ------------------------------------------------
                &Header::openbox('100%', 'left', 'NAT');
                print<<END;
                        <label>
                                <input type='checkbox' name='USE_NAT' id='USE_NAT' value="ON" $checked{'USE_NAT'}{'ON'}>
                                $Lang::tr{'fwdfw use nat'}
                        </label>
                        <div class="NAT"> <===========  div class "NAT" 
                                <table class='fw-nat' width='100%' border='0'>
                                        <tr>
                                                <td width='5%'></td>
                                                <td width='40%'>
                                                        <label>
                                                                <input type='radio' name='nat'  value='dnat' $checked{'nat'}{'dnat'}>
                                                                $Lang::tr{'fwdfw dnat'}
                                                        </label>
                                                </td>
END

        print <<END;
                                                <td width='25%' align='right'><span class='dnat'>$Lang::tr{'dnat address'}:</span></td>
                                                <td width='30%'>
                                                        <select name='dnat' class='dnat' style='width: 100%;'> <====class dnat
                                                                <option value='AUTO' $selected{'dnat'}{'AUTO'}>- $Lang::tr{'automatic'} -</option>
                                                                <option value='Default IP' $selected{'dnat'}{'Default IP'}>$Lang::tr{'red1'} ($redip)</option>
END
                if (%aliases) {
                        foreach my $alias (sort keys %aliases) {
                                print "<option value='$alias' $selected{'dnat'}{$alias}>$alias ($aliases{$alias}{'IPT'})</option>";
                        }
                }
                #DNAT Dropdown
                foreach my $network (sort keys %defaultNetworks)
                {
                        if ($defaultNetworks{$network}{'NAME'} eq 'BLUE'||$defaultNetworks{$network}{'NAME'} eq 'GREEN' ||$defaultNetworks{$network}{'NAME'} eq 'ORANGE'){
                                print "<option value='$defaultNetworks{$network}{'NAME'}'";
                                print " selected='selected'" if ($fwdfwsettings{'dnat'} eq $defaultNetworks{$network}{'NAME'});
                                print ">$network ($defaultNetworks{$network}{'NET'})</option>";
                        }
                }
                print "</select>";
                print "</tr>";




...

                #SNAT
                print <<END;
                                        <tr>
                                                <td width='5%'></td>
                                                <td width='40%'>
                                                        <label>
                                                                <input type='radio' name='nat'  value='snat' $checked{'nat'}{'snat'}>
                                                                $Lang::tr{'fwdfw snat'}
                                                        </label>
                                                </td>
                                                <td width='25%' align='right'><span class='snat'>$Lang::tr{'snat new source ip address'}:</span></td>
                                                <td width='30%'>
                                                        <select name='snat' class='snat' style='width: 100%;'>
                                                                <option value='RED' $selected{'snat'}{'RED'}>$Lang::tr{'red1'} ($redip)</option>
END



                # SNAT Dropdown
                foreach my $network (sort keys %defaultNetworks) {
                        if ($defaultNetworks{$network}{'NAME'} eq 'BLUE'||$defaultNetworks{$network}{'NAME'} eq 'GREEN' ||$defaultNetworks{$network}{'NAME'} eq 'ORANGE'){
                                print "<option value='$defaultNetworks{$network}{'NAME'}'";
                                print " selected='selected'" if ($fwdfwsettings{'snat'} eq $defaultNetworks{$network}{'NAME'});
                                print ">$network ($defaultNetworks{$network}{'NET'})</option>";
                        }
                }
                print <<END;
                                                        </select>
                                                </td>
                                        </tr>
                                </table>
                        </div>
END


4,ACCEPT,FORWARDFW,ON,src_addr,10.0.0.1/32,tgt_addr,192.168.1.150/32,ON,TCP,,12345,ON,,,TGT_PORT,8080,TEST RULE,ON,ON,on,on,on,on,on,on,on,00:15,00:45,ON,AUTO,8090,dnat,ON,10,ON,10,second


ACCEPT,			$fwdfwsettings{'RULE_ACTION'}		0
FORWARDFW,		$fwdfwsettings{'chain'}			1
ON,			$fwdfwsettings{'ACTIVE'}		2
src_addr,		$fwdfwsettings{'grp1'}			3
10.0.0.1/32,		$fwdfwsettings{$fwdfwsettings{'grp1'}}  4
tgt_addr,		$fwdfwsettings{'grp2'}			5
192.168.1.150/32,	$fwdfwsettings{$fwdfwsettings{'grp2'}}	6
ON,			$fwdfwsettings{'USE_SRC_PORT'}		7
TCP,			$fwdfwsettings{'PROT'}			8
,			$fwdfwsettings{'ICMP_TYPES'}		9
12345,			$fwdfwsettings{'SRC_PORT'}		10
ON,			$fwdfwsettings{'USESRV'}		11
,			$fwdfwsettings{'TGT_PROT'}		12
,			$fwdfwsettings{'ICMP_TGT'}		13
TGT_PORT,		$fwdfwsettings{'grp3'}			14
8080,			$fwdfwsettings{$fwdfwsettings{'grp3'}}	15
TEST RULE,		$fwdfwsettings{'ruleremark'}		16
ON,			$fwdfwsettings{'LOG'}			17
ON,			$fwdfwsettings{'TIME'}			18
on,			$fwdfwsettings{'TIME_MON'}		19
on,			$fwdfwsettings{'TIME_TUE'}		20
on,			$fwdfwsettings{'TIME_WED'}		21
on,			$fwdfwsettings{'TIME_THU'}		22
on,			$fwdfwsettings{'TIME_FRI'}		23
on,			$fwdfwsettings{'TIME_SAT'}		24
on,			$fwdfwsettings{'TIME_SUN'}		25
00:15,			$fwdfwsettings{'TIME_FROM'}		26
00:45,			$fwdfwsettings{'TIME_TO'}		27
ON,			$fwdfwsettings{'USE_NAT'}		28
AUTO,			$fwdfwsettings{$fwdfwsettings{'nat'}}	29
8090,			$fwdfwsettings{'dnatport'}		30
dnat,			$fwdfwsettings{'nat'}			31
ON,			$fwdfwsettings{'LIMIT_CON_CON'}		32
10,			$fwdfwsettings{'concon'}		33
ON,			$fwdfwsettings{'RATE_LIMIT'}		34
10,			$fwdfwsettings{'ratecon'}		35
second			$fwdfwsettings{'RATETIME'}		36
