# OC-SSH

SSH Protocol (RFC4250) that can connect to real computers in Minecraft! (with the mod OpenComputer)

Written in pure Lua and APIs available in OpenOS.

Currently, only `password` auth is supported, probably will add `publickey` in the future. Since OpenComputer stores the computer files (the Minecraft computer) directly in the Minecraft server host's computer (the IRL computer), supporting `publickey` implies the Minecraft server host can directly copy your SSH private key from your files, which is not a good idea.

Note: In any circumstance, you SHOULD only use this script in a Minecraft server host you trust. Running it on an untrusted Minecraft server host exposes vulnerability to the host, which allows the host to gain access to your remote machine if the host wants to do so.

---
# Usage
```
ssh [username@]<host> [port]
```

![image](https://github.com/user-attachments/assets/958bc3c0-2532-41c8-b84a-efa6c97b65e6)
