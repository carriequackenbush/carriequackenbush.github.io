---
title: Mine Over Matter
date: 2025-05-17 10:37:02 -0700
categories: [BYUCTF]
tags: [basic, forensics]     # TAG names should always be lowercase
---
![byuctf Logo](/assets/img/logo-byuctf.png){: .right }
>Your SOC has flagged unusual outbound traffic on a segment of your network. After capturing logs from the router during the anomaly, they handed it over to you—the network analyst.
>Somewhere in this mess, two compromised hosts are secretly mining cryptocurrency and draining resources. Analyze the traffic, identify the two rogue IP addresses running miners, and report them to the Incident Response team before your network becomes a crypto farm.
>Flag format: byuctf{IP1,IP2} (it doesn't matter what order the IPs are in)

This used the same log format that was featured in Are You Looking Me Up. Since it was clear what was the incoming IP this was just a matter of identifying the column that looked like data amounts, sorting that column from highest to lowest, and seeing that two incoming IPs repeated over and over.
