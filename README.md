# ThreadlessOps II- Enhanced Evasion

In this second part of Threadless Ops, we combine threadless injection with several evasion techniques to bypass typical EDR heuristics. As a foundation, we use the PIC framework Crystal Palace, which acts as a linker and lets us modularly integrate tradecraft such as call-stack spoofing and additional resources into our loader. In addition, we apply module stomping and the Caro-Kann principle to delay the decryption and execution of the payload inside trustworthy working memory, so that simple memory scans come up empty. Finally, we run a practical test against Elastic Defend, followed by a classification of the most important IOCs and mitigations.

Part 1:  [ThreadlessOps - Enhanced Shellcoding for Threadless Injections](https://github.com/sanackermann/ThreadlessOps/tree/Part1)


## 📖 Blog Post

🔗 [ThreadlessOps II: Enhanced Evasion](https://avantguard.io/en/blog/threadless-ops-ii-enhanced-evasion)

🔗 [ThreadlessOps II: Enhanced Evasion (German)](https://avantguard.io/blog/threadless-ops-ii-enhanced-evasion)

## 🔬 What this part covers

- Why EDRs detect shellcode activity
- Using **call stack spoofing** to avoid detections for sensitive API calls
- Creating backed memory by loading an additional module
- **Overwriting a dispensable region** inside that module and executing from backed memory
- Using a **new thread** as a pragmatic compromise
  - Preserves both the original control flow and the payload execution
- A separate **Caro-Kann stub** that waits ~5 seconds, then decrypts and executes the payload
  - Intended to reduce hits from simple/static memory scans shortly after thread creation
- Mitigations
  - Correlate suspicious injection patterns
  - Detect call stack spoofing
  - Enforce CET / Shadow Stack to break stack tampering techniques
  - Detect module stomping

## 🙏 Credits

This project builds upon and was inspired by the incredible work of:

- **Raphael Mudge**
- **Daniel Duggan (Rasta Mouse)**
- **NtDallas**
- **Ceri Coburn (CCob)**
- **Yoann Dequeker (OtterHacker)**
- **Fabian Mosch (S3cur3Th1sSh1t)**
- **Caue Borella**
- **Chetan Nayak (ParanoidNinja)**

## ⚠️ Disclaimer

This project is intended **for educational and research purposes only**. Use responsibly and only in environments where you have explicit authorization. The authors are not liable for any misuse.
