# EAA

## Preface

This repository provides the implementation of [our EAA protocol](https://). This implementation is based on [SPDZ-2](https://github.com/bristolcrypto/SPDZ-2). To fulfill our additional functionalities, we also realized a type of offline tuples (**Rand**). 


## Requirements
- OS: Ubuntu 16.04 LTS
- GCC, version 7.4.0
- MPIR library, version 2.7.2
- libsodium library, version 1.0.11
- NTL library, **version 11.0.0 (exact)**
- valgrind, version 3.14.0
- OPENSSL, version 1.1.1b


## To compile EAA
Download this repository and run the following commands in shell.
```bash
cd eaa/
make clean && make all
```

For further compilation details about SPDZ, see [README.md](https://github.com/bristolcrypto/SPDZ-2) in [SPDZ-2](https://github.com/bristolcrypto/SPDZ-2).

## To benchmark EAA

### Offline phase of EAA
(**Rand**) is generated under the framework of Low Gear. To benchmark their generation, one can run `pairwise-offline.x` with the following parameters:

| -r                            | To generate **Rand** tuples instead of default **Triple**
| -nr [N_RANDS]                 | Number of **Rand**s to be generated (default: 131072)

Shares of output tuples, FHE parameters and MAC key share can be found in folders named `[N_PARTIES]-[FIELD_SIZE]-[STATISTIC_SEC]` in `eaa/Player-Data/`.

#### Some examples

To generate 1024 **Rand**s in 2-parties setting (LAN/WAN), in which each party works with 16 threads and the field size of 70, run
```bash
# On party 0
./pairwise-offline.x -o -h [Party_0_HOST] -x 1 -f 70 -N 2 -p 0 -nr 1000000 -r
# On party 1
./pairwise-offline.x -o -h [Party_0_HOST] -x 1 -f 70 -N 2 -p 1 -nr 1000000 -r
```

### Online phase of EAA
#### Simple local example
To test the functionality of EAA protocol of online phase, say, $10^6$ encoders with around $10^2$ buckets of histogram and two aggregators in one local machine.

Run the offline phase to generate the necessary offline data first. To note, we only need enough rand triples, that is, we need $10^8$ rand triples in this scenario.

First open a new cmd and start the Names server which establishs the communication network between Computation parties.
```bash
./Server.x 2 5000 1
```

Open two new cmd and run the computation parties
```bash
./CP.x  -lgp 70 -np 2 -p 0 -sec 40 -ndp 1 -oM 1 -uN 1000000 -lan 1 -nt 1 
./CP.x  -lgp 70 -np 2 -p 1 -sec 40 -ndp 1 -oM 1 -uN 1000000 -lan 1 -nt 1
```

In the cmd run Names server, run the data party
```bash
./DP.x -ndp 1 -ncp 2 -p 1 -lgp 70 -oM 1 -uN 1000000 -nt 1
```

#### parameters for Names server
```bash
./Server.x {number of aggregators} 5000 {number of threads}
```

#### parameters for Computation party
```bash
./CP.x  -lgp {length-bits of the secrete sharing} -np {number of aggregators} -p {party number} -sec {security level} -ndp {number of data parties} -oM {number of buckets of histogram} -uN {number of encoders} -lan {whether in lan environment} -nt {number of threads} -h {ip of Data party}
```

#### parameters for Data party
```bash
./DP.x -ndp {number of data parties} -ncp {number of aggregators} -p {party number} -lgp {length-bits of the secrete sharing} -oM {number of buckets of histogram} -uN {number of encoders} -ip {ip files}
```



