| year | descr | target | link | CVE |
| --- | --- | --- | --- | --- |
| 1991 | Bass-O-Matic flaws | Bass-O-Matic cipher | https://en.wikipedia.org/wiki/BassOmatic | |
| 2000 | ADK key manipulation | PGP 5.x | http://senderek.ie/research/security/key-experiments.html | [CVE-2000-0678](https://nvd.nist.gov/vuln/detail/CVE-2000-0678) |
| 2001 | Surreptitious Forwarding | OpenPGP + Mail | https://www.usenix.org/legacy/publications/library/proceedings/usenix01/full_papers/davis/davis.pdf | |
| 2002 | Attack on Private Signature Keys | Keyring encryption | https://eprint.iacr.org/2002/076 | |
| 2003 | ElGamal sign+encrypt keys broken | GnuPG | https://nvd.nist.gov/vuln/detail/CVE-2003-0971 | [CVE-2003-0971](https://nvd.nist.gov/vuln/detail/CVE-2003-0971) |
| 2005 | CFB Quick Check weakness | OpenPGP CFB encryption | https://eprint.iacr.org/2005/033 | [CVE-2005-0366](https://nvd.nist.gov/vuln/detail/CVE-2005-0366) |
| 2012 | shared RSA moduli | Glück und Kanja PGP | https://eprint.iacr.org/2012/064 https://blog.hboeck.de/archives/872-About-the-supposed-factoring-of-a-4096-bit-RSA-key.html https://eprint.iacr.org/2015/262 https://www.links.org/?p=143 | |
| 2013 | trollwot | Web of Trust / Keyservers | https://github.com/micahflee/trollwot | |
| 2014 | Evil32 | Short Key IDs | https://evil32.com/ | |
| 2015 | DSA duplicate k | 1 key of unknown origin | https://eprint.iacr.org/2015/262 | |
| 2015 | SEIP downgrade | OpenPGP standard | https://www.metzdowd.com/pipermail/cryptography/2015-October/026685.html | |
| 2015 | Format Oracles | Various implementations | https://www.ssi.gouv.fr/uploads/2015/05/format-Oracles-on-OpenPGP.pdf | |
| 2016 | Entropy Loss | GnuPG / Libgcrypt | https://formal.iti.kit.edu/~klebanov/pubs/libgcrypt-cve-2016-6313.pdf | [CVE-2016-6313](https://nvd.nist.gov/vuln/detail/CVE-2016-6313) |
| 2018 | efail | OpenPGP + HTML mail | https://efail.de/ | [CVE-2017-17688](https://nvd.nist.gov/vuln/detail/CVE-2017-17688) |
| 2018 | SigSpoof | GnuPG API interface | https://web.archive.org/web/20180616202842/https://neopg.io/blog/gpg-signature-spoof/ | [CVE-2018-12020](https://nvd.nist.gov/vuln/detail/CVE-2018-12020) |
| 2019 | UI trust extrapolation | Evolution mail client | https://dev.gentoo.org/~mgorny/articles/evolution-uid-trust-extrapolation.html | |
| 2019 | Johnny, you are fired | OpenPGP signatures | https://www.usenix.org/conference/usenixsecurity19/presentation/muller | |
| 2019 | Re: What's up Johnny? | Email encryption | https://www.nds.ruhr-uni-bochum.de/research/publications/re-whats-up-johnny/ | |
| 2019 | Keyserver DoS | SKS keyservers | https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f | [CVE-2019-13050](https://nvd.nist.gov/vuln/detail/CVE-2019-13050) |
| 2019 | Plaintext injection | python-gnupg | https://blog.hackeriet.no/cve-2019-6690-python-gnupg-vulnerability/ | [CVE-2019-6690](https://nvd.nist.gov/vuln/detail/CVE-2019-6690) |

more
====

An interesting list of older PGP issues can be found here:
* http://www.mccune.cc/PGPpage2.htm

The "Security Consederations" section of the
OpenPGP specification RFC 4880 is also interesting:
* https://tools.ietf.org/html/rfc4880#section-14

Boring bugs
===========

This list focusses on bugs that stand out and are interesting, though
all PGP implementations obviously had common programming bugs like
typical memory corruptions. To not clutter the list we list them separately here:

* [CVE-2002-0685/PGP: Heap-based buffer overflow in the message decoding functionality for PGP Outlook Encryption Plug-In](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0685)
* [CVE-2014-9087/libksba/GnuPG: Integer underflow in the ksba_oid_to_str function in Libksba](https://nvd.nist.gov/vuln/detail/CVE-2014-9087)
* [CVE-2015-1606/GnuPG: Invalid read / use after free in keyring parser](https://nvd.nist.gov/vuln/detail/CVE-2015-1606)
* [CVE-2015-1607/GnuPG: Invalid read in keyring parser](https://nvd.nist.gov/vuln/detail/CVE-2015-1607)
