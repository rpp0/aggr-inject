aggr-inject
===========

aggr-inject is a proof-of-concept implementation of the A-MPDU subframe injection attack, which allows an attacker to inject raw Wi-Fi frames into unencrypted networks remotely. The PoC exploits a vulnerability in the 802.11n frame aggregation mechanism and can be performed against almost any modern Wi-Fi chipset, given that the target is connected to an open network. Results from this research were published in a paper and presented at the ACM WiSec 2015 security conference.


Background
----------

A regular 802.11n Wi-Fi frame looks as follows:

![alt text](https://github.com/rpp0/aggr-inject/blob/master/images/plcp.png "Regular 802.11n Wi-Fi frame")

The 802.11n standard specifies a new MAC frame (MPDU) aggregation mechanism intended to decrease overhead when transmitting multiple frames. In essence, the sender will aggregate multiple MPDUs in a single PHY frame as follows:

![alt text](https://github.com/rpp0/aggr-inject/blob/master/images/ampdu.png "A-MPDU frame aggregation")

Here, each subframe is prepended with a delimiter in order to indicate its starting position and length inside the aggregated frame. When the receiver receives the aggregate, the delimiters are removed, and each subframe is deaggregated and forwarded to the kernel for further processing.


Vulnerability
-------------

The deaggregation algorithm specified in the standard is flawed because the MPDU delimiters are transmitted with the same data rate and modulation method as the frame payload. This allows us to create our own subframes (low layer frames) within any higher layer e.g. HTTP, FTP, ICMP, etc. In other words, we can embed a malicious MAC frame including the delimiter inside an outer frame, for example a HTTP frame. When such frames are aggregated, any bit error in the delimiter of the outer frame will cause the receiver to interpret our malicious, inner frame instead!

![alt text](https://github.com/rpp0/aggr-inject/blob/master/images/attack.png "Packet-in-packet style attack")

An example scenario of how an attack could be performed is shown below. Here, the attacker serves a .jpg file containing malicious frames on a web server. When the .jpg is downloaded, the receiver will see the attacker's malicious frames with every occurence of a bit error in the HTTP subframe delimiter.

![alt text](https://github.com/rpp0/aggr-inject/blob/master/images/setup.gif "Attack scenario")
<br/>
<sup>Thanks to https://github.com/zhovner for creating this animation!</sup>


Consequences
------------

Depending on whether the attacker knows the MAC address of the targeted network's AP, several attacks can be performed using aggr-inject:
- Deauthenticate clients
- Inject malicious Beacon frames (e.g. overly long SSID field)
- Perform a host or port scan
- Bypass firewall rules
- ARP spoofing
- ...

All of these attacks can be performed remotely and without owning a wireless device, since the deaggregation happens at the final hop and since it does not matter how the packet travels to its destination. 


Practical proof-of-concept
--------------------------

If you want to see the attack in action on your own network, run option 1 of the PoC to generate the image file containing Beacon subframes (300 MB), then upload it to your web server. Finally, download the image **while being connected to an open 802.11n network with frame aggregation enabled**. Then, while downloading, check either Wireshark or your list of discovered networks (usually takes several downloads of the image for it to appear in the list of networks), and you should see a new network named "injected SSID" coming from MAC address 00:00:00:00:00:00. The amount of Beacons you see will depend on how fast frames are corrupted on your network and how often your AP performs frame aggregation.


Details
-------

More details about the attack can be found in my paper at [this location](https://github.com/rpp0/aggr-inject/blob/master/paper/ampdu_inj_wisec2015.pdf). My presentation can be downloaded [here](https://github.com/rpp0/aggr-inject/blob/master/presentation/wisec2015.pdf).


Contact
-------

I'm happy to answer any questions via the Reddit thread concerning this attack (https://www.reddit.com/r/netsec/comments/3bq96e/vulnerability_in_80211n_standard_allows_remote/), Twitter (https://twitter.com/redplusplus) or my e-mail, which you can find at the end of my presentation.
