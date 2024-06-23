import socket
import subprocess

restrictions = dict()

# Add restrictions here: 
# 
# e.g.
#
# restrictions['ltorvalds'] =  ['www.microsoft.com', 'www.git-sucks.com']
#
#



def create_ipset4(username):
    """
    Create an ipset for a given username, configured for ipv4

    :param username:
    :return: the name of the ipset
    """
    setname = username+"_ipv4_blocklist"

    subprocess.run(["ipset", "-exist", "create", setname, "hash:ip", "family", "inet"], check=True)
    subprocess.run(["ipset", "flush", setname], check=True)

    return setname


def create_ipset6(username):
    """
    Create an ipset for a given username, configured for ipv6

    :param username:
    :return: the name of the ipset
    """

    setname = username + "_ipv6_blocklist"

    subprocess.run(["ipset", "-exist", "create", setname, "hash:ip", "family", "inet6"], check=True)
    subprocess.run(["ipset", "flush", setname], check=True)

    return setname


def get_ips(domains):
    """
    Get a list of ips for the provided domains
    :param domains: A list of domain names
    :return:  A list of IPs associated with the provided domains,
              possibly multiple addresses for the one domain,
              both IPv4 and IPv6
    """
    ret = set()
    for domain in domains:
        (hostname, aliaslist, ipaddrlist) = socket.gethostbyname_ex(domain)
        for ip in ipaddrlist:
            ret.add(ip)
    return ret


def add_ip_to_set(ip, set):
    subprocess.run(["ipset", "-exist", "add", set, ip], check=True)

def add_rule(cmd, user, set):
    """
    Add an iptables rule that prevents the provided user from visiting IPs on the provided set

    :param cmd: iptables command, e.g. "iptables" or "ip6tables"
    :param user: username to be restricted
    :param set:  ipset name
    """

    rule = ["-m", "set", "--match-set", set, "dst", "-m", "owner", "--uid", user, "-j", "DROP"]
    try:
        subprocess.run([cmd, "-C", "OUTPUT"] + rule, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        subprocess.run([cmd, "-A", "OUTPUT"] + rule)


for user in restrictions:
    ipset4 = create_ipset4(user)
    ipset6 = create_ipset6(user)

    ips = get_ips(restrictions[user])

    for ip in ips:
        if ip.find(":") >= 0:
            add_ip_to_set(ip, ipset6)
        else:
            add_ip_to_set(ip, ipset4)

    add_rule("iptables", user, ipset4)
    add_rule("ip6tables", user, ipset6)

