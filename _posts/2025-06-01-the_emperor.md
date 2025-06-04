---
title: The Emperor
date: 2025-06-01 10:35:00 -0700
categories: [N0PSctf]
tags: [basic, cryptography]     # TAG names should always be lowercase
---
![N0PSctf Logo](/assets/img/logo-nopsctf.png){: .right }
> Ahoye! Here are the crypto newbies! Today, we are learning the basics of cryptography! Here is an encrypted message for you, try to decipher it. Learning this will help you on the day you will face CrypTopia.

```
Ea, kag pqoapqp uf tgt?
Ftqz, tqdq ue ftq rxms:
UVGEFPQOAPQPMOMQEMDOUBTQDITUOTYMWQEYQMBDARQEEUAZMXODKBFATQDA
```

[DCode's cipher identifier](https://www.dcode.fr/cipher-identifier) identified this as a ROT cipher, and choosing that decrypted the whole thing.

[CyberChef](https://cyberchef.org/#recipe=ROT13(true,true,false,14)&input=RWEsIGthZyBwcW9hcHFwIHVmIHRndD8KRnRxeiwgdHFkcSB1ZSBmdHEgcnhtczoKVVZHRUZQUU9BUFFQTU9NUUVNRE9VQlRRRElUVU9UWU1XUUVZUU1CREFSUUVFVUFaTVhPREtCRkFUUURB) solved it as well, after changing the amount of ROT. 
