Configuration companyOpsFirewallConfig
{
	Import-DscResource -Name 'xFirewall';	
	xFirewall NPMDFirewallRule
	{
			Name                  = 'NPMDFirewallRule'
			DisplayName           = 'NPMD Firewall port exception'
			Ensure                = 'Present'
			Enabled               = 'True'
			Profile               = ('Domain', 'Private')
			Direction             = 'InBound'
			LocalPort             = ('8084')
			Protocol              = 'TCP'
			Description           = 'NPMD Firewall port exception'
			Program               = 'NPMDAgent.exe'
			EdgeTraversalPolicy   = 'Block'
			Owner                 = 'S-1-5-32-544'
	}
	Import-DscResource -Name 'xFirewall';
	xFirewall NPMDICMPV4DestinationUnreachable
	{
			Name                  = 'NPMDICMPV4DestinationUnreachable'
			DisplayName           = 'NPMD ICMPv4 Destionation Unreachable'
			Ensure                = 'Present'
			Enabled               = 'True'
			Profile               = ('Domain', 'Public', 'Private')
			Direction             = 'InBound'
			Protocol              = 'ICMPv4'
			Description           = 'NPMD Firewall port exception'
			EdgeTraversalPolicy   = 'Block'
			Owner                 = 'S-1-5-32-544'
			IcmpType							= '3'
	}
	Import-DscResource -Name 'xFirewall';
	xFirewall ICMPv4TimeExceededRuleName
	{
			Name                  = 'ICMPv4TimeExceededRuleName'
			DisplayName           = 'NPMD ICMPv4 Time Exceeded'
			Ensure                = 'Present'
			Enabled               = 'True'
			Profile               = ('Domain', 'Public', 'Private')
			Direction             = 'InBound'
			Protocol              = 'ICMPv4'
			Description           = 'NPMD ICMPv4 Time Exceeded'
			EdgeTraversalPolicy   = 'Block'
			Owner                 = 'S-1-5-32-544'
			IcmpType							= '11'
	}
	Import-DscResource -Name 'xFirewall';
	xFirewall NPMDICMPV6DestinationUnreachable
	{
			Name                  = 'ICMPv6DestinationUnreachableRuleName'
			DisplayName           = 'NPMD ICMPv6 Destionation Unreachable'
			Ensure                = 'Present'
			Enabled               = 'True'
			Profile               = ('Domain', 'Public', 'Private')
			Direction             = 'InBound'
			Protocol              = 'ICMPv6'
			Description           = 'NPMD ICMPv6 Destionation Unreachable'
			EdgeTraversalPolicy   = 'Block'
			Owner                 = 'S-1-5-32-544'
			IcmpType							= '1'
	}
	Import-DscResource -Name 'xFirewall';
	xFirewall ICMPv6TimeExceededRuleName
	{
			Name                  = 'ICMPv6TimeExceededRuleName'
			DisplayName           = 'NPMD ICMPv6 Time Exceeded'
			Ensure                = 'Present'
			Enabled               = 'True'
			Profile               = ('Domain', 'Public', 'Private')
			Direction             = 'InBound'
			Protocol              = 'ICMPv6'
			Description           = 'NPMD ICMPv6 Time Exceeded'
			EdgeTraversalPolicy   = 'Block'
			Owner                 = 'S-1-5-32-544'
			IcmpType							= '3'
	}

}
