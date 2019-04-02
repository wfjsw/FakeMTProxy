# FakeMTProxy

Simulate MTProxy traffic.

To simulate ordinary connection without `dd` use `-p` with `abridged`  
To simulate current `dd` implemention, use `-p -ps` and `-psl` (optional) with `secure`  

Note:  
Client and server should have same `-ps` and `-psl` flags. Other flag / options should be set client-side.
