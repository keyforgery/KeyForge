# KeyForge Keyserver

KeyForge is a Forward Forgeable Signature protocol -- a scheme to create signatures that are only valid for a limited time. After the time is up, the private key is publicly disclosed, and *any* attacker could easily forge the signature. 

A paper describing our technique is currently in submission. This repo is for anonymous review only.

## Installation 
The easiest way to install and test our code is by using the Dockerfile. 

Otherwise, please see the liger subdirectory for how to install the Go-RELIC pairing-based cryptography bridge.


## Multi-hop SMTP Dataset Analysis

We find that multihop SMTP (that is, mail for which email is sent through a third-party MTA) appears to be used in roughly 22% of the mail servers in the alexa top ~150k. See the results.csv file for raw dns lookup data.

Of the alexa top ~150k domains, 31,615 have MX records, of these, roughly 7000 are using one of the below confirmed multihop providers:


| Company     |  mx domain 				| count  |
| ----------- | ----------- 				| ------ |
| Microsoft    | outlook.com        		| 3676|
| Proofpoint   | pphosted.com     & ppe-hosted.com   		| 1407 |
| Barracuda   |  barracudanetworks.com  | 173 |
| Mimecast   |  mimecast.com        		 | 721 |
| Symantec  |  MessageLabs.com        | 341 |
| MailControl  |  MailControl.com        | 91 |
| Mailgun  |  Mailgun.org        | 241 |
| Postini  |  psmtp.com        | 143 |


This is a conservative estimate based on what could be confirmed quickly, the real number is likely higher -- there are many smaller multihop spam-filtering providers that are not included in the above estimates. 


