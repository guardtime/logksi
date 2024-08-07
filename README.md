# KSI Log Signature Command-line Tool

Guardtime's KSI Blockchain is an industrial scale blockchain platform that cryptographically ensures data integrity and proves time of existence. The KSI signatures, based on hash chains, link data to this global calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term integrity of any digital asset without the need to trust any system.

There are many applications for KSI, a classical example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, see [https://guardtime.com](https://guardtime.com)

Log signature command-line tool `logksi` provides the functions for creating log signatures; signing recovery; extension of KSI signatures in the log signature file; verification of logs; extraction of record-level signatures; integration of log signature files.


## INSTALLATION

### Latest Release from Guardtime Repository

In order to install the `logksi` CentOS/RHEL packages directly from the Guardtime public repository, download and save the repository configuration to the `/etc/yum.repos.d/` folder:

```
cd /etc/yum.repos.d

# In case of RHEL/CentOS 7
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el7.repo

# In case of RHEL/CentOS 8
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el8.repo

# In case of RHEL/CentOS 9
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el9.repo

yum install logksi
```

In order to install the `logksi` Debian package:

```
# Add Guardtime pgp key.
sudo curl https://download.guardtime.com/ksi/GUARDTIME-GPG-KEY-2 | sudo apt-key add -

# In case of Debian 12 (Bookworm)
sudo curl -o /etc/apt/sources.list.d/guardtime.list https://download.guardtime.com/ksi/configuration/guardtime.bookworm.list

sudo apt update
apt-get install logksi
```

For macOS, see [https://github.com/guardtime/homebrew-ksi](https://github.com/guardtime/homebrew-ksi)


### From Source Code

If the latest version is needed or the package is not available for the platform you are using, check out source code from Github and build it using `gcc`. To build the KSI log signature command-line tool, `libksi-devel` (KSI C SDK) and `libgtrfc3161-devel` packages are needed. 

* `libksi` is available in Guardtime repository or as source code in GitHub: [https://github.com/GuardTime/libksi](https://github.com/GuardTime/libksi). 
* `libgtrfc3161` is available in Guardtime GitHub: [https://github.com/guardtime/libgtrfc3161](https://github.com/guardtime/libgtrfc3161).

Use `rebuild.sh` script to build `KSI log signature command-line tool` and see `rebuild.sh -h` for more details (use flags `--get-dep-online -s` to get `libksi` and `libgtrfc3161` from GitHub automatically without installing the libraries).

See `test/TEST-README.md` to learn how to run `logksi` tests.


## USAGE

In order to get trial access to the KSI platform, go to
[https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers)

The first argument of the KSI log signature command-line tool is the `logksi` command, which is followed by the KSI service configuration parameters and options.

For example, to add missing KSI signatures to a log signature file:

```
logksi sign logfile [ksioptions]
```

See `man logksi` for detailed usage instructions.


## LICENSE

See `LICENSE` file.


## CONTRIBUTING

See `CONTRIBUTING.md` file.


## DEPENDENCIES

```
Library   Version    License type  Source

libksi       >=3.20     Apache 2.0    https://github.com/GuardTime/libksi
libgtrfc3161 >=1.0      Apache 2.0    https://github.com/GuardTime/libgtrfc3161
OpenSSL      >=0.9.8    BSD           https://github.com/openssl/
Curl         >=7.37.0   MIT           https://github.com/curl/curl.git
```

* Note 1: OpenSSL is `libksi` dependency.
  This product includes software developed by the OpenSSL Project for use
  in the OpenSSL Toolkit (http://www.openssl.org/). This product includes
  cryptographic software written by Eric Young (eay@cryptsoft.com). This
  product includes software written by Tim Hudson (tjh@cryptsoft.com).

* Note 2: `Curl` is `libksi` dependency.


## COMPATIBILITY

```
OS/Platform                         Compatibility

CentOS/RHEL 7,8,9, x86_64 architecture  Fully compatible and tested.
Debian 12+                              Fully compatible and tested.
Ubuntu                                  Compatible but not tested on regular basis.
OS X                                    Compatible but not tested on regular basis.
Windows                                 Not supported.
```