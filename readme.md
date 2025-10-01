# Bait Shop

Toy project to experiment with lnk phising and pdf polyglots.

the builder.ps1 script generate a valid pdf file that contains obfuscated vbscript. The builder script also generate a lnk file that execute the code contained in the pdf file with mshta.exe.

This kind of phising technique has been used by several threat actors in the past few years, and recent EDRs should easily detect it. It is still a funny and instructive exemple of how certains file formats can be abused to hide malicious payloads.

![Execution flow](assets/lnk-phishing.drawio.png)

## ref

- https://www.proofpoint.com/us/blog/threat-insight/call-it-what-you-want-threat-actor-delivers-highly-targeted-multistage-polyglot
- https://arxiv.org/html/2407.01529v1

## TODO

- better cli interface
- add other polyglots (pptm, docx)
- better obfuscation lol