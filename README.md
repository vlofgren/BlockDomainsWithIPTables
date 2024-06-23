# BlockDomainsWithIPTables

Simple utility for blocking IP addresses associated with a domain for a single user on a Linux system using iptables.  This was a bit tricky to figure out how to do so I figured I would share my solution.  

It's not intended for e.g. setting up a parental filter, I mostly use it to restrict my own activity so I can't scroll social media on my work user account, to promote more deliberate computer activity...

The utility adds filters to the OUTPUT chain in iptables and ip6tables that prevents a specified user from accessing any of the IPs associated with a domain.

You also to edit `main.py` to configure the users and restrictions.

You should have a basic understanding of iptables to use this utility, although unless you've added a script that persists the IPtables changes, they should normally reset each time you restart.
