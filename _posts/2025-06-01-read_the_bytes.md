---
title: Read the Bytes!
date: 2025-06-01 10:37:00 -0700
categories: [N0PSctf]
tags: [basic, re, reverse, engineering]     # TAG names should always be lowercase
---

> Look who's there! New students! Fine, this time we will focus on reverse engineering. This could help you against PwnTopia one day! I give you now a Python program and its output. Try to understand how it works!
```
from flag import flag

# flag = b"XXXXXXXXXX"

for char in flag:
    print(char)

# 66
# 52
# 66
# 89
# 123
# 52
# 95
# 67
# 104
# 52
# 114
# 97
# 67
# 55
# 51
# 114
# 95
# 49
# 115
# 95
# 74
# 117
# 53
# 116
# 95
# 52
# 95
# 110
# 85
# 109
# 56
# 51
# 114
# 33
# 125
```
There were probably many and smarter ways to do this, but I just took the numbers and put them into [DCode](https://www.dcode.fr/ascii-code) which revealed the flag.
