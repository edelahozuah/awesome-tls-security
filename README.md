# awesome-tls-security
A collection of (not-so, yet) awesome resources related to TLS, PKI and related stuff

# Table of Contents

[You should read this an skip the rest of the list](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/reviewerKit.html)

## Trends

[Looking Back, Moving Forward (2017)](https://casecurity.org/2017/01/13/2017-looking-back-moving-forward/)

## Pervasive Monitoring
[Pervasive Monitoring is an Attack. RFC 7258](https://tools.ietf.org/html/rfc7258)

[Confidentiality in the Face of Pervasive Surveillance: A Threat Model and Problem Statement. RFC 7624 (2015)](https://tools.ietf.org/html/rfc7624)


## Certificates / PKIX

[Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile. RFC 5280](https://doi.org/10.17487/rfc5280)

[Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS). RFC 6125](https://doi.org/10.17487/rfc6125)

[tls - How does OCSP stapling work? - Information Security Stack Exchange. (2013)](https://security.stackexchange.com/questions/29686/how-does-ocsp-stapling-work)

## Attacks on TLS

### Overview

[SSL/TLS Vulnerabilities](https://www.gracefulsecurity.com/tls-ssl-vulnerabilities/)  

[ATTACKS ON SSL A COMPREHENSIVE STUDY OF BEAST, CRIME, TIME, BREACH, LUCK Y 13 & RC4 BIASES](https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/ssl_attacks_survey.pdf)


### Recent Attacks

#### TLS/SSL

[On the Practical (In-)Security of 64-bit Block Ciphers: Collision Attacks on HTTP over TLS and OpenVPN (SWEET32, 2016)](https://sweet32.info/SWEET32_CCS16.pdf)

[Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS). RFC 7457 (2015)](https://doi.org/10.17487/rfc7457 )

[DROWN: Breaking TLS Using SSLv2 (DROWN, 2016)](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/aviram)

[All Your Biases Belong to Us: Breaking RC4 in WPA-TKIP and TLS (RC4NOMORE, 2015)](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/vanhoef)

[Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice (LOGJAM, 2015)](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf)

[A messy state of the union: Taming the composite state machines of TLS (2015)](http://www.ieee-security.org/TC/SP2015/papers-archived/6949a535.pdf)

[Bar Mitzvah Attack: Breaking SSL with a 13-year old RC4 Weakness (2015)](https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf)

[This POODLE bites: exploiting the SSL 3.0 fallback (POODLE, 2014)](https://www.openssl.org/~bodo/ssl-poodle.pdf)

[Lucky Thirteen: Breaking the TLS and DTLS Record Protocols (Lucky13, 2013](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf) 

[SSL, gone in 30 seconds. Breach attack (BREACH,2013)](http://news.asis.io/sites/default/files/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides_0.pdf)

[On the Security of RC4 in TLS (2013)](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/alFardan)

[The CRIME Attack (CRIME, 2012)](https://www.ekoparty.org/archive/2012/CRIME_ekoparty2012.pdf)

[Here come the ⊕ Ninjas (BEAST, 2011)](http://nerdoholic.org/uploads/dergln/beast_part2/ssl_jun21.pdf)

### Software Vulnerabilities


[Java’s SSLSocket: How Bad APIs compromise security (2015)](https://deepsec.net/docs/Slides/2014/Java's_SSLSocket_-_How_Bad_APIs_Compromise_Security_-_Georg_Lukas.pdf)

[A Survey on {HTTPS} Implementation by Android Apps: Issues and Countermeasures](https://www.researchgate.net/publication/309895574_A_Survey_on_HTTPS_Implementation_by_Android_Apps_Issues_and_Countermeasures) 


## PKIX

### Incidents

[Secure» in Chrome Browser Does Not Mean «Safe» (2017)](https://www.wordfence.com/blog/2017/03/chrome-secure/ )

[Intent to Deprecate and Remove: Trust in existing Symantec-issued Certificates (Symantec, 2017)](https://groups.google.com/a/chromium.org/forum/#!topic/blink-dev/eUAKwjihhBs)

[Incidents involving the CA WoSign (WoSign, 2016)](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/k9PBmyLCi8I%5B1-25%5D)

[Sustaining Digital Certificate Security (Symantec, 2015)](https://security.googleblog.com/2015/10/sustaining-digital-certificate-security.html)

[Improved Digital Certificate Security (Symantec, 2015)](https://security.googleblog.com/2015/09/improved-digital-certificate-security.html)

[TURKTRUST Unauthorized CA Certificates. (2013)](https://www.entrust.com/turktrust-unauthorized-ca-certificates/)

[Flame malware collision attack explained (FLAME, 2012)](https://blogs.technet.microsoft.com/srd/2012/06/06/flame-malware-collision-attack-explained/
)

[An update on attempted man-in-the-middle attacks (DIGINOTAR, 2011)](https://security.googleblog.com/2011/08/update-on-attempted-man-in-middle.html)

[Detecting Certificate Authority compromises and web browser collusion (COMODO, 2011)](https://blog.torproject.org/blog/detecting-certificate-authority-compromises-and-web-browser-collusion)

## SSL Interception

### Remarkable works

[Certified lies: Detecting and defeating government interception attacks against ssl (2011)](http://files.cloudprivacy.net/ssl-mitm.pdf)

[The Security Impact of HTTPS Interception (2017)](https://zakird.com/papers/https_interception.pdf)

[US-CERT TA17-075A Https interception weakens internet security (2017)](https://www.us-cert.gov/ncas/alerts/TA17-075A) 

[ Killed by Proxy: Analyzing Client-end TLS Interception Software (2016)](https://madiba.encs.concordia.ca/~x_decarn/papers/tls-proxy-ndss2016.pdf)

[TLS interception considered harmful How Man-in-the-Middle filtering solutions harm the security of HTTPS (2015)](https://events.ccc.de/camp/2015/Fahrplan/events/6833.html) 

[The Risks of SSL Inspection (2015)](https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html) 

[TLS in the wild—An Internet-wide analysis of TLS-based protocols for electronic communication (2015)]()

[The Matter of Heartbleed (2014)](https://jhalderm.com/pub/papers/heartbleed-imc14.pdf)

[How the NSA, and your boss, can intercept and break SSL (2013)](http://www.zdnet.com/article/how-the-nsa-and-your-boss-can-intercept-and-break-ssl/)

### SSL Interception-related Incidents

[Komodia superfish ssl validation is broken (2015)](https://blog.filippo.io/komodia-superfish-ssl-validation-is-broken/)

[More TLS Man-in-the-Middle failures - Adguard, Privdog again and ProtocolFilters.dll (2015)](https://blog.hboeck.de/archives/874-More-TLS-Man-in-the-Middle-failures-Adguard,-Privdog-again-and-ProtocolFilters.dll.html)

[Software Privdog worse than Superfish (2015)](https://blog.hboeck.de/archives/865-Software-Privdog-worse-than-Superfish.html)

[Superfish 2.0: Dangerous Certificate on Dell Laptops breaks encrypted HTTPS Connections (2015)](https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html)

[How Kaspersky makes you vulnerable to the FREAK attack and other ways Antivirus software lowers your HTTPS security (2015)](https://blog.hboeck.de/archives/869-How-Kaspersky-makes-you-vulnerable-to-the-FREAK-attack-and-other-ways-Antivirus-software-lowers-your-HTTPS-security.htm)

## Tools
### TLS Audit

#### Online

[Qualys SSL Server Test](https://www.ssllabs.com/ssltest/)

[Qualys SSL Client Test](https://www.ssllabs.com/ssltest/viewMyClient.html)

#### Local

[sslyze](https://github.com/iSECPartners/sslyze)

[Qualys SSL Labs (local version)](https://github.com/ssllabs/ssllabs-scan)

[testssl.sh](https://testssl.sh/)

### Sysadmins

[Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

[IISCrypto: Tune up your Windows Server TLS configuration](https://www.nartac.com/Products/IISCrypto)

### MITM
[bettercap - A complete, modular, portable and easily extensible MITM framework’](https://www.bettercap.org/)

[dns2proxy](https://github.com/LeonardoNve/dns2proxy)

[MITMf](https://github.com/byt3bl33d3r/MITMf)


## Protocols

### UTA (Use TLS in Applications) IETF WG

[Drafts and RFCs (HTTP and SMTP)](https://datatracker.ietf.org/wg/uta/documents/)

### Strict Transport Security (STS)

[HTTP Strict Transport Security (HSTS). RFC 6797 (2012)](https://doi.org/10.17487/rfc6797)

[STS Preload List - Google Chrome](https://cs.chromium.org/chromium/src/net/http/transport_security_state_static.json)

[HSTS Preload List Submission.](https://hstspreload.org/)

[HTTP Strict Transport Security for Apache, NGINX and Lighttpd](https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html) 



### HPKP

[Public Key Pinning Extension for HTTP. RFC 7469 (2015)](https://doi.org/10.17487/rfc7469)

[Is HTTP Public Key Pinning Dead? (2016)](https://blog.qualys.com/ssllabs/2016/09/06/is-http-public-key-pinning-dead)

### Certificate Transparency

[Certificate Transparency](https://www.certificate-transparency.org/) 

[How Certificate Transparency Works - Certificate Transparency](https://www.certificate-transparency.org/how-ct-works)

[Google Certificate Transparency (CT) to Expand to All Certificates Types (2016)](https://casecurity.org/2016/11/08/google-certificate-transparency-ct-to-expand-to-all-certificates-types/)

### CAA

[DNS Certification Authority Authorization (CAA) Resource Record. RFC 6844](https://doi.org/10.17487/rfc6844)

[CAA Record Generator](https://sslmate.com/labs/caa/)

### DANE and DNSSEC

[DANE Resources](https://www.huque.com/dane/)

[The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA. RFC 6698](https://doi.org/10.17487/rfc6698)

[DANE: Taking TLS Authentication to the Next Level Using DNSSEC (2011)](https://www.internetsociety.org/articles/dane-taking-tls-authentication-next-level-using-dnssec)

[Generate TLSA Record](https://www.huque.com/bin/gen_tlsa)

[DNS security introduction and requirements. RFC 4033](https://tools.ietf.org/html/rfc4033)
