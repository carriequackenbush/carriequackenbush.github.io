---
title: Unknown File
date: 2025-06-01 10:36:00 -0700
categories: [N0PSctf]
tags: [basic, forensics]     # TAG names should always be lowercase
---
![N0PSctf Logo](/assets/img/logo-nopsctf.png){: .right }
> Hello young trainees! Today, we are studying digital forensics! This may be useful if one day you have to face PwnTopia... Here is a file, you have to find a way to read its content. Good luck!

![First part of the extensionless file as code](/assets/img/2025-06-01-unknown_file.png)
The file itself had no extension. As it was a reasonable size, it could just be opened in Notepad++ and the file signature in the beginning revealed that it was a PDF. From there it was just a matter of adding an extension and opening the file, which revealed the flag.
