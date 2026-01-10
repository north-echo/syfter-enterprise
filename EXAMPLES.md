Some examples.

Scanning the RHEL 10.0 x86_64 RPM release tree
```
❯ time rh-syfter scan /tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -p rhel -v 10.0
╭──────────────────────────────────────────────────────────────────────────────────────────── RH-Syfter Scan ─────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: /tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64                                                                                                                │
│ Product: rhel-10.0                                                                                                                                                                                      │
│ CPE Prefix: cpe:2.3:o:redhat:rhel:10.0                                                                                                                                                                  │
│ PURL Qualifier: distro=rhel-10.0                                                                                                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: directory
Found 14243 RPM files
Using syft version: 1.40.0
Running: syft dir:/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -o syft-json --source-name rhel-10.0 --source-version 10.0 --catalogers rpm
Flag --catalogers has been deprecated, use: override-default-catalogers and select-catalogers
 ✔ Indexed file system                                                                                            /private/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 
 ✔ Cataloged contents                                                                                                                   8fa27bc8a624bdb983b42e698df2cffdc01df57b6d5800bd7211e14a0d10d226 
   ├── ✔ Packages                        [14,243 packages]  
   ├── ✔ Executables                     [0 executables]  
   ├── ✔ File metadata                   [14,243 locations]  
   └── ✔ File digests                    [14,243 files]  
[0000]  WARN adding 'file' tag to the default cataloger selection, to override add '-file' to the cataloger selection request
Modified 14243 artifacts with product metadata
Compressed SBOMs: original 321.0MB, modified 320.9MB
Stored scan #1: 14243 packages, 8391958 files
✓ Scan #1 stored successfully
rh-syfter scan  -p rhel -v 10.0  345.62s user 113.53s system 173% cpu 4:25.25 total
```

Scanning a container:
```
❯ time rh-syfter scan registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3 \
  -p multicluster-globalhub -v 1.4.3 --source skopeo 
╭────────────────────────────────────────────────────────────────────────────────────────────── RH-Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3                                                                                                                │
│ Product: multicluster-globalhub-1.4.3                                                                                                                                                                       │
│ CPE Prefix: cpe:2.3:o:redhat:multicluster-globalhub:1.4.3                                                                                                                                                   │
│ PURL Qualifier: distro=multicluster-globalhub-1.4.3                                                                                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: container
Pulling image with skopeo (linux/amd64)...
Image pulled successfully
Using syft version: 1.40.0
Running: syft oci-dir:/Users/redhat/tmp/rh-syfter-wprrikqq/image -o syft-json --source-name multicluster-globalhub-1.4.3 --source-version 1.4.3
 ✔ Parsed image                                                                                                                      sha256:370faa6f0c42dc7495ca233dd47246326cbb88f4c225a7f14785085d5253b58d 
 ✔ Cataloged contents                                                                                                                       79c3507442159eb7f3106636e3f5ece58ce84e246233b233618a92b99a3e1f13 
   ├── ✔ Packages                        [233 packages]  
   ├── ✔ Executables                     [263 executables]  
   ├── ✔ File metadata                   [1,161 locations]  
   └── ✔ File digests                    [1,161 files]  
Modified 233 artifacts with product metadata
Compressed SBOMs: original 0.2MB, modified 0.2MB
Stored scan #2: 233 packages, 2907 files
✓ Scan #2 stored successfully
rh-syfter scan  -p multicluster-globalhub -v 1.4.3 --source skopeo  4.56s user 1.89s system 55% cpu 11.631 total
```

Searching for the `sshd` binary:

```
❯ time rh-syfter query -f '%sbin/sshd'                                                                                              
                                  File Search Results                                  
                                                                                       
  Path             Package                           Product     Digest                
 ───────────────────────────────────────────────────────────────────────────────────── 
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.0   bb8034e17fd665d14fd…  
                                                                                       
rh-syfter query -f '%sbin/sshd'  1.31s user 0.23s system 99% cpu 1.542 total
```

Searching for `libzma.so`:

```
❯ time rh-syfter query -f '%liblzma.so' 
                           File Search Results                            
                                                                          
  Path                    Package                     Product     Digest  
 ──────────────────────────────────────────────────────────────────────── 
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.0           
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.0           
                                                                          
rh-syfter query -f '%liblzma.so'  1.20s user 0.21s system 99% cpu 1.418 total
```

Searching for the `openldap` package:

```
❯ time rh-syfter query -n 'openldap'
                                                Package Search Results                                                 
                                                                                                                       
  Name       Version                 Arch     Product                        PURL                                      
 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  openldap   0:2.6.8-3.el10-3.el10   x86_64   rhel-10.0                      pkg:rpm/redhat/openldap@2.6.8-3.el10?ar…  
  openldap   2.6.8-4.el9-4.el9       x86_64   multicluster-globalhub-1.4.3   pkg:rpm/redhat/openldap@2.6.8-4.el9?arc…  
                                                                                                                       
rh-syfter query -n 'openldap'  0.09s user 0.03s system 95% cpu 0.119 total
```

See the statistics of what's in the database (and for reference, how big it is on-disk):

```
❯ rh-syfter stats              
╭──────────────────────────────────────────────────────────────────────────────────────────── Database Statistics ────────────────────────────────────────────────────────────────────────────────────────────╮
│ Database: /Users/redhat/.rh-syfter/syfter.db                                                                                                                                                                │
│ Products: 2                                                                                                                                                                                                 │
│ Scans: 2                                                                                                                                                                                                    │
│ Packages: 14476                                                                                                                                                                                             │
│ Files: 8394865                                                                                                                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
❯ du -sh ~/.rh-syfter/syfter.db
3.4G	/Users/redhat/.rh-syfter/syfter.db
```

Export the internal syft SBOM format from the database to all export formats:

```
❯ time rh-syfter export -p rhel -v 10.0 -f all -o output/
Converting to spdx-json...
Wrote spdx-json to output/rhel-10.0.spdx.json
Converting to spdx-tag-value...
Wrote spdx-tag-value to output/rhel-10.0.spdx
Converting to cyclonedx-json...
Wrote cyclonedx-json to output/rhel-10.0.cdx.json
Converting to cyclonedx-xml...
Wrote cyclonedx-xml to output/rhel-10.0.cdx.xml
Exported to 4 formats:
  - spdx-json: output/rhel-10.0.spdx.json
  - spdx-tag-value: output/rhel-10.0.spdx
  - cyclonedx-json: output/rhel-10.0.cdx.json
  - cyclonedx-xml: output/rhel-10.0.cdx.xml
rh-syfter export -p rhel -v 10.0 -f all -o output/  695.69s user 25.76s system 100% cpu 11:59.90 total
```