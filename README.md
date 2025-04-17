# ThreadlessOps - Enhanced Shellcoding for Threadless Injections

**ThreadlessOps** is a project demonstrating advanced process injection techniques with custom shellcode. While the initial focus is on **threadless injection**, this project goes beyond that by exploring enhanced shellcode crafting.


**Threadless Injection** is a stealthy method that avoids creating new threads by hijacking existing execution contexts within a target process. This reduces the likelihood of detection but requires more complex shellcode.

However, ThreadlessOps is not limited to threadless execution alone. In practice, we reintroduce thread creation to increase compatibility with various payloads. 

## 📖 Blog Post

We discuss the motivation, implementation, and technical background in detail here:  
🔗 [ThreadlessOps - Enhanced Shellcoding for Threadless Injections](https://avantguard.io/en/blog/threadless-ops)

## 🙏 Credits

This project builds upon and was inspired by the incredible work of:

- **Ceri Coburn (CCob)**
- **Yoann Dequeker (OtterHacker)**
- **Fabian Mosch (S3cur3Th1sSh1t)**
- **Caue Borella**
- **Chetan Nayak (ParanoidNinja)**

## ⚠️ Disclaimer

This project is intended **for educational and research purposes only**. Use responsibly and only in environments where you have explicit authorization. The authors are not liable for any misuse.
