---
title: Are You Looking Me Up?
date: 2025-05-17 10:36:01 -0700
categories: [BYUCTF]
tags: [basic, forensics]     # TAG names should always be lowercase
---
![byuctf Logo](/assets/img/logo-byuctf.png){: .right }
> The network has a DNS server that's been receiving a lot of traffic. You've been handed a set of raw network logs. Your job? Hunt down the DNS server that has received the most DNS requests.

I love log. For this challenge, the log was pretty standard but didn't have headers. 

This was just a matter of looking at the log and determining which IP was incoming and which was outgoing. The port was fairly easy to identify as the server ports were all pretty low.
