---
title: End of the Line
date: 2025-06-19 10:36:01 -0700
categories: [USCyber]
tags: [ctf, forensics, basic]     # TAG names should always be lowercase
---
#![US Cyber Games Logo](/assets/img/logo-uscybergames.png){: .right }

There was no description to this, just a wav file. Listening to the wav file made clear that it was Morse code, which I first transcribed by hand and then confirmed with a wav to Morse website converter. 

> ... -.- .-.- --- .-. --.- - .. .-.- -. ..- -.. -. .-- .-. ...- -... ...

Translating the Morse didn't reveal anything, but as suggested by the title of the challenge, reversing the order did. 

> ... ...- -... .-. --. .- ..- -.. .- -.-. .. - -.-- .-. --- -.-. -.- ...

Based on the flag, you were supposed to use Audacity, but I just manually typed the Morse backwards. Translating the 'backwards' Morse did reveal the flag.
