Some examples.

## Scanning an RPM-based distro

Scanning the RHEL 10.0 x86_64 RPM release tree

```
❯ time syfter scan /tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -p rhel -v 10.0
╭──────────────────────────────────────────────────────────────────────────────────────────────── Syfter Scan ────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: /tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64                                                                                                                    │
│ Product: rhel-10.0                                                                                                                                                                                          │
│ Mode: Server                                                                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: directory
Found 14243 RPM files (11097 non-debug)
Using syft version: 1.40.0
Running: syft dir:/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -o syft-json --source-name rhel-10.0 --source-version 10.0 --override-default-catalogers rpm-archive-cataloger
 ✔ Indexed file system                                                                                                /private/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 
 ✔ Cataloged contents                                                                                                                       8fa27bc8a624bdb983b42e698df2cffdc01df57b6d5800bd7211e14a0d10d226 
   ├── ✔ Packages                        [14,243 packages]  
   ├── ✔ Executables                     [0 executables]  
   ├── ✔ File metadata                   [14,243 locations]  
   └── ✔ File digests                    [14,243 files]  
[0000]  WARN adding 'file' tag to the default cataloger selection, to override add '-file' to the cataloger selection request
Excluded 3146 debug packages (debuginfo/debugsource)
Excluded 3146 debug source files
Modified 11097 artifacts with product metadata
Preparing upload: 11097 packages, 6424406 files
Creating import job...
Job created: 6dfcbff6-797d-4274-9959-d6dd39d63e36
Building TSV files...
TSV built: packages=400.2KB, files=215399.0KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (328739.5KB)...
  Uploading modified_sbom (240639.2KB)...
  Uploading packages_tsv (400.2KB)...
  Uploading files_tsv (215399.0KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #22 uploaded to server (job: 6dfcbff6-797d-4274-9959-d6dd39d63e36)
syfter scan  -p rhel -v 10.0  448.09s user 112.35s system 75% cpu 12:26.30 total
```

## Scanning a container

Scanning the `multicluster-globalhub-agent` container direct from the Container Catalog:

```
❯ time syfter scan registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3 \
  -p multicluster-globalhub -v 1.4.3 --source skopeo
╭────────────────────────────────────────────────────────────────────────────────────────────── Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3                                                                                                                │
│ Product: multicluster-globalhub-1.4.3                                                                                                                                                                       │
│ Mode: Server                                                                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: container
Pulling image with skopeo (linux/amd64)...
Image pulled successfully
Using syft version: 1.40.0
Running: syft oci-dir:/Users/redhat/tmp/syfter-k_17g2go/image -o syft-json --source-name multicluster-globalhub-1.4.3 --source-version 1.4.3
 ✔ Parsed image                                                                                                                      sha256:370faa6f0c42dc7495ca233dd47246326cbb88f4c225a7f14785085d5253b58d 
 ✔ Cataloged contents                                                                                                                       79c3507442159eb7f3106636e3f5ece58ce84e246233b233618a92b99a3e1f13 
   ├── ✔ Packages                        [233 packages]  
   ├── ✔ Executables                     [263 executables]  
   ├── ✔ File digests                    [1,161 files]  
   └── ✔ File metadata                   [1,161 locations]  
Modified 233 artifacts with product metadata
Preparing upload: 233 packages, 2907 files
Creating import job...
Job created: 0afddb1a-6ebc-4c59-9f2f-0d8a32dea0cd
Building TSV files...
TSV built: packages=9.3KB, files=63.5KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (244.6KB)...
  Uploading modified_sbom (244.0KB)...
  Uploading packages_tsv (9.3KB)...
  Uploading files_tsv (63.5KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #23 uploaded to server (job: 0afddb1a-6ebc-4c59-9f2f-0d8a32dea0cd)
syfter scan  -p multicluster-globalhub -v 1.4.3 --source skopeo  4.78s user 1.66s system 44% cpu 14.623 total
```

## Scanning a container with automatic base image tracking

When scanning a multi-layer container like `go-toolset`, syfter automatically detects the base image chain and determines which image contributed each package:

```
❯ time syfter scan registry.redhat.io/rhel9/go-toolset:1.25 \
  -p go-toolset -v 1.25 --source skopeo
╭────────────────────────────────────────────────────────────────────────────────────────────── Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: registry.redhat.io/rhel9/go-toolset:1.25                                                                                                                                                          │
│ Product: go-toolset-1.25                                                                                                                                                                                    │
│ Mode: Server                                                                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: container
Pulling image with skopeo (linux/amd64)...
Image pulled successfully
Using syft version: 1.40.0
Running: syft oci-dir:/Users/redhat/tmp/syfter-1kb9hzsi/image -o syft-json --source-name go-toolset-1.25 --source-version 1.25
 ✔ Parsed image                                                                                                                      sha256:9e9d00aa4282077195e9700a4740bdf43555e79390afcb515b86226c8d2f5302 
 ✔ Cataloged contents                                                                                                                       682aab8265d43b7b9b34b556ea5cd17a587b2d259b9eee9e8ee88124de9764e1 
   ├── ✔ Packages                        [676 packages]  
   ├── ✔ Executables                     [1,283 executables]  
   ├── ✔ File metadata                   [21,666 locations]  
   └── ✔ File digests                    [21,666 files]  
Excluded 1 debug packages (debuginfo/debugsource)
Excluded 81 debug source files
Modified 675 artifacts with product metadata
Found 4 container layers
Packages with layer info: 675/675
Checking 9 candidate base images...
Verified image chain: ubi9/ubi → ubi9/s2i-core → ubi9/s2i-base → rhel9/go-toolset
Scanning base images to determine package provenance...
  Scanning: registry.redhat.io/ubi9/ubi:9.7-1767674301...
    Found 187 packages (187 new)
  Scanning: registry.redhat.io/ubi9/s2i-core:1-1767713898...
    Found 204 packages (17 new)
  Scanning: registry.redhat.io/ubi9/s2i-base:1-1768264882...
    Found 419 packages (215 new)
Determined source images for 624 packages
Packages with source image: 675/675
Preparing upload: 675 packages, 33614 files
Creating import job...
Job created: afd12f58-e509-4339-9415-5224b0da9446
Building TSV files...
TSV built: packages=27.6KB, files=1148.9KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (3663.6KB)...
  Uploading modified_sbom (3647.2KB)...
  Uploading packages_tsv (27.6KB)...
  Uploading files_tsv (1148.9KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #41 uploaded to server (job: afd12f58-e509-4339-9415-5224b0da9446)
syfter scan registry.redhat.io/rhel9/go-toolset:1.25 -p go-toolset -v 1.25  51.16s user 18.15s system 37% cpu 3:04.02 total
```

Now queries show the source image for each package:

```
❯ time syfter query -n 'go%' -p go-toolset -v 1.25
                            Package Search Results                             
                                                                               
  Name                    Version          Product           Source Image      
 ───────────────────────────────────────────────────────────────────────────── 
  go-srpm-macros          3.6.0-12.el9_7   go-toolset-1.25   ubi9/s2i-base     
  go-toolset              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  gobject-introspection   1.68.0-11.el9    go-toolset-1.25   ubi9/ubi          
  golang                  1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-bin              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-race             1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
  golang-src              1.25.3-1.el9_7   go-toolset-1.25   rhel9/go-toolset  
                                                                               
syfter query -n 'go%' -p go-toolset -v 1.25  0.15s user 0.04s system 86% cpu 0.216 total

❯ time syfter query -n '%git' -p go-toolset -v 1.25
                       Package Search Results                        
                                                                     
  Name          Version          Product           Source Image      
 ─────────────────────────────────────────────────────────────────── 
  @npmcli/git   6.0.3            go-toolset-1.25   rhel9/go-toolset  
  git           2.47.3-1.el9_6   go-toolset-1.25   ubi9/s2i-base     
                                                                     
syfter query -n '%git' -p go-toolset -v 1.25  0.15s user 0.04s system 88% cpu 0.215 total
```

This tells you that if you need to fix a vulnerability in `gobject-introspection`, you need to update the `ubi9/ubi` base image, not the `go-toolset` container itself.  Likewise, if you're looking to fix `git` it's in the intermediary `ubi9/s2i-base` container, not the base `ubi9/ubi` or the `go-toolset` container.

### Viewing the container layer chain

Use the `layers` command to see the complete layer chain for a container:

```
❯ time syfter layers -p go-toolset -v 1.25                
╭─────────────────────────────────────────────────────────────────────────────────────────── Container Layer Chain ───────────────────────────────────────────────────────────────────────────────────────────╮
│ Container: registry.redhat.io/rhel9/go-toolset:1.25                                                                                                                                                         │
│ Layers: 4                                                                                                                                                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                              
  #     Layer ID          Source Image       Version   Image Reference (copy/paste)                           
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  0     a6cca9262fdd6     ubi9/ubi           9.7       registry.redhat.io/ubi9/ubi:9.7-1767674301             
  1     efa697a554ff9     ubi9/s2i-core      1         registry.redhat.io/ubi9/s2i-core:1-1767713898          
  2     0ab3ef6ff04cf     ubi9/s2i-base      1         registry.redhat.io/ubi9/s2i-base:1-1768264882          
  3     45d7e18dbaad7     rhel9/go-toolset   1.25.3    registry.redhat.io/rhel9/go-toolset:1.25.3-1768393489  
                                                                                                              

Unique source images: 4
  • rhel9/go-toolset -> registry.redhat.io/rhel9/go-toolset:1.25.3-1768393489
  • ubi9/s2i-base -> registry.redhat.io/ubi9/s2i-base:1-1768264882
  • ubi9/s2i-core -> registry.redhat.io/ubi9/s2i-core:1-1767713898
  • ubi9/ubi -> registry.redhat.io/ubi9/ubi:9.7-1767674301
syfter layers -p go-toolset -v 1.25  0.16s user 0.04s system 86% cpu 0.227 total
```

This shows the complete image chain: `ubi9/ubi` → `ubi9/s2i-core` → `ubi9/s2i-base` → `rhel9/go-toolset`, with each layer attributed to the image that introduced it. The full image references include the exact version-release tags.

## Scanning a Middleware ZIP archive

Scanning the EAP 8.1 ZIP archive:

```
❯ time syfter scan -p eap -v 8.1 jboss-eap-8.1.0.zip                                                   
╭────────────────────────────────────────────────────────────────────────────────────────────── Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: jboss-eap-8.1.0.zip                                                                                                                                                                               │
│ Product: eap-8.1                                                                                                                                                                                            │
│ Mode: Server                                                                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: archive
Using syft version: 1.40.0
Running: syft jboss-eap-8.1.0.zip -o syft-json --source-name eap-8.1 --source-version 8.1
 ✔ Indexed file system                                                                                                                                      /Users/redhat/tmp/syft-archive-contents-49858061 
 ✔ Cataloged contents                                                                                                                       9b5ed0c66db9dbac8d01c3c13aa0fc7b3f0dc7a307b5d59d270897be990ddd43 
   ├── ✔ Packages                        [869 packages]  
   ├── ✔ Executables                     [7 executables]  
   ├── ✔ File metadata                   [674 locations]  
   └── ✔ File digests                    [674 files]  
Modified 869 artifacts with product metadata
Preparing upload: 869 packages, 0 files
Creating import job...
Job created: 8889663a-6563-4814-8e69-d9be63ba4ea8
Building TSV files...
TSV built: packages=32.9KB, files=0.0KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (689.1KB)...
  Uploading modified_sbom (654.4KB)...
  Uploading packages_tsv (32.9KB)...
Starting import job...
Processing in background, polling for status...
✓ Scan #24 uploaded to server (job: 8889663a-6563-4814-8e69-d9be63ba4ea8)
syfter scan -p eap -v 8.1 jboss-eap-8.1.0.zip  11.75s user 8.92s system 184% cpu 11.177 total
```

## Searching for files

Searching for the `sshd` binary:

```
❯ time syfter query -f '%sbin/sshd'  
                      File Search Results                       
                                                                
  Path             Package                           Product    
 ────────────────────────────────────────────────────────────── 
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.1  
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.0 
```

Searching for `libzma.so`:

```
❯ time syfter query -f '%liblzma.so' 
                       File Search Results                       
                                                                 
  Path                    Package                     Product    
 ─────────────────────────────────────────────────────────────── 
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.0  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.0  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.1  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.1  
                                                                 
syfter query -f '%liblzma.so'  0.16s user 0.04s system 9% cpu 2.131 total
```

## Searching for packages

Searching for the `openldap` package:

```
❯ time syfter query -n 'openldap'    
                   Package Search Results                   
                                                            
  Name       Version          Product                       
 ────────────────────────────────────────────────────────── 
  openldap   2.6.8-4.el9      multicluster-globalhub-1.4.3  
  openldap   0:2.6.8-3.el10   rhel-10.0                     
  openldap   0:2.6.8-3.el10   rhel-10.1 
```

## Statistics

See the statistics of what's in the database (and for reference, how big it is on-disk):

```
❯ syfter stats
╭──────────────────────────────────────────────────────────────────────────────────────────────── Statistics ─────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Mode: Server                                                                                                                                                                                                │
│ Database: postgresql                                                                                                                                                                                        │
│ Storage: s3                                                                                                                                                                                                 │
│ Products: 5                                                                                                                                                                                                 │
│ Scans: 5                                                                                                                                                                                                    │
│ Packages: 23420                                                                                                                                                                                             │
│ Files: 12851719                                                                                                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Exporting SBOMs

Export the internal syft SBOM format from the database to all export formats:

```
❯ time syfter export -p rhel -v 10.0 -f all -o output/
Converting to spdx-json...
Converting to spdx-tag-value...
Converting to cyclonedx-json...
Converting to cyclonedx-xml...
✓ Exported to 4 formats in output/rhel-10.0.json/
  output/rhel-10.0.json/rhel-10.0.spdx.json
  output/rhel-10.0.json/rhel-10.0.spdx
  output/rhel-10.0.json/rhel-10.0.cdx.json
  output/rhel-10.0.json/rhel-10.0.cdx.xml
syfter export -p rhel -v 10.0 -f all -o output/  532.54s user 20.74s system 99% cpu 9:14.95 total
```

## System Mode (Infrastructure Scanning)

Syfter can also be used to scan and track packages across your infrastructure.

### Scanning the Localhost

Scan the local host and tag it for grouping:

```
❯ syfter system-scan --tag production
╭────────────────────────────── Syfter System Scan ──────────────────────────────╮
│ Scanning: localhost                                                               │
│ Hostname: webserver01.example.com                                                 │
│ IP: 192.168.1.50                                                                  │
│ OS: Linux 6.5.0-14-generic                                                        │
│ Tag: production                                                                   │
╰───────────────────────────────────────────────────────────────────────────────────╯
Scanning localhost (webserver01.example.com)...
Using syft version: 1.40.0
...
✓ System scan #1 uploaded to server (job: abc123...)
```

### Scanning a Remote Host via SSH

Scan a remote host by providing the hostname or IP:

```
❯ syfter system-scan git.annvix.ca --tag personal -u vdanen
Getting info from remote host git.annvix.ca...
╭─────────────────────────────────────────────────────────────────────────────────────────── Syfter System Scan ───────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: git.annvix.ca                                                                                                                                                                                     │
│ Hostname: git.annvix.ca                                                                                                                                                                                     │
│ IP: git.annvix.ca                                                                                                                                                                                           │
│ OS: Linux 6.18.2-0-virt                                                                                                                                                                                     │
│ Tag: personal                                                                                                                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Connecting to vdanen@git.annvix.ca...
Remote syft version: 1.38.0
Running remote scan on git.annvix.ca...
Remote scan complete
Modified 1169 artifacts with product metadata
Preparing upload: 1169 packages, 27610 files
Creating system import job...
Job created: 8de237e7-def4-4444-8aeb-f679ebe94ec7
Building TSV files...
TSV built: packages=34.2KB, files=700.3KB
Compressing SBOMs...
Uploading files to storage...
  Uploading original_sbom (2547.6KB)...
  Uploading modified_sbom (2524.2KB)...
  Uploading packages_tsv (34.2KB)...
  Uploading files_tsv (700.3KB)...
Starting import job...
Processing in background, polling for status...
✓ System scan #25 uploaded to server (job: 8de237e7-def4-4444-8aeb-f679ebe94ec7)
```

### Listing Systems

View all scanned systems:

```
❯ syfter systems                                            
                                                   Systems                                                    
                                                                                                              
  Hostname         IP               Tag        OS                             Packages    Files   Last Scan   
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  git.annvix.ca    192.168.250.22   personal   Linux 6.18.2-0-virt                1169   27,610   2026-01-13  
  plex.annvix.ca   192.168.250.20   personal   Linux 6.17.9-300.fc43.x86_64       1275   89,296   2026-01-13 
```

### Querying Packages Across Systems

Find which systems have a specific package installed:

```
❯ syfter system-query -n 'openssh-server'
                System Package Search Results                 
                                                              
  Name             Version         System           Tag       
 ──────────────────────────────────────────────────────────── 
  openssh-server   10.2_p1-r0      git.annvix.ca    personal  
  openssh-server   10.0p1-6.fc43   plex.annvix.ca   personal     
```

### Filtering by Tag

Find packages only in personal systems:

```
❯ syfter system-query -n 'kernel' -t personal                
              System Package Search Results              
                                                         
  Name     Version            System           Tag       
 ─────────────────────────────────────────────────────── 
  kernel   6.17.12-300.fc43   plex.annvix.ca   personal  
  kernel   6.17.8-300.fc43    plex.annvix.ca   personal  
  kernel   6.17.9-300.fc43    plex.annvix.ca   personal
```

### Listing Packages for a Specific System

```
❯ syfter system-list -H plex.annvix.ca -t packages | head -20
ModemManager-1.24.2-1.fc43
ModemManager-glib-1.24.2-1.fc43
NetworkManager-1:1.54.3-2.fc43
NetworkManager-bluetooth-1:1.54.3-2.fc43
...
```

### Finding Files Across Systems

Search for specific files across your infrastructure:

```
❯ syfter system-query -f '%bin/sshd'
                         System File Search Results                          
                                                                             
  Path             Package                        System           Tag       
 ─────────────────────────────────────────────────────────────────────────── 
  /usr/bin/sshd    openssh-server-10.0p1-6.fc43   plex.annvix.ca   personal  
  /usr/sbin/sshd   openssh-server-10.2_p1-r0      git.annvix.ca    personal  
```