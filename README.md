# Fluhrer, Mantin and Shamir .rs
This is an implementation of the Fluhrer, Mantin and Shamir attack used to break WEP keys. It takes as input a massive pcap file and a key size. The pcap file should contain WEP traffic filtered to only packets containing the IV.

<!-- TODO explain how the attack works maybe? -->

### Resources
 - https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack
 - https://www.mattblaze.org/papers/others/rc4_ksaproc.pdf
 - https://people.computing.clemson.edu/~westall/851/stubblefield01using.pdf
