Some examples.

## Scanning an RPM-based distro

Scanning the RHEL 10.0 x86_64 RPM release tree

```
❯ time rh-syfter scan /tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64 -p rhel -v 10.0
╭────────────────────────────────────────────────────────────────────────────────────────────── RH-Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
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
rh-syfter scan  -p rhel -v 10.0  448.09s user 112.35s system 75% cpu 12:26.30 total
```

## Scanning a container

Scanning the `multicluster-globalhub-agent` container direct from the Container Catalog:

```
❯ time rh-syfter scan registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3 \
  -p multicluster-globalhub -v 1.4.3 --source skopeo
╭────────────────────────────────────────────────────────────────────────────────────────────── RH-Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
│ Scanning: registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3                                                                                                                │
│ Product: multicluster-globalhub-1.4.3                                                                                                                                                                       │
│ Mode: Server                                                                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Source type: container
Pulling image with skopeo (linux/amd64)...
Image pulled successfully
Using syft version: 1.40.0
Running: syft oci-dir:/Users/redhat/tmp/rh-syfter-k_17g2go/image -o syft-json --source-name multicluster-globalhub-1.4.3 --source-version 1.4.3
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
rh-syfter scan  -p multicluster-globalhub -v 1.4.3 --source skopeo  4.78s user 1.66s system 44% cpu 14.623 total
```
## Scanning a Middleware ZIP archive

Scanning the EAP 8.1 ZIP archive:

```
❯ time rh-syfter scan -p eap -v 8.1 jboss-eap-8.1.0.zip                                                   
╭────────────────────────────────────────────────────────────────────────────────────────────── RH-Syfter Scan ───────────────────────────────────────────────────────────────────────────────────────────────╮
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
rh-syfter scan -p eap -v 8.1 jboss-eap-8.1.0.zip  11.75s user 8.92s system 184% cpu 11.177 total
```

## Searching for files

Searching for the `sshd` binary:

```
❯ time rh-syfter query -f '%sbin/sshd'  
                      File Search Results                       
                                                                
  Path             Package                           Product    
 ────────────────────────────────────────────────────────────── 
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.1  
  /usr/sbin/sshd   openssh-server-0:9.9p1-7.el10_0   rhel-10.0 
```

Searching for `libzma.so`:

```
❯ time rh-syfter query -f '%liblzma.so' 
                       File Search Results                       
                                                                 
  Path                    Package                     Product    
 ─────────────────────────────────────────────────────────────── 
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.0  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.0  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-3.el10     rhel-10.1  
  /usr/lib64/liblzma.so   xz-devel-1:5.6.2-4.el10_0   rhel-10.1  
                                                                 
rh-syfter query -f '%liblzma.so'  0.16s user 0.04s system 9% cpu 2.131 total
```

## Searching for packages

Searching for the `openldap` package:

```
❯ time rh-syfter query -n 'openldap'    
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
❯ rh-syfter stats
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
❯ time rh-syfter export -p rhel -v 10.0 -f all -o output/
Converting to spdx-json...
Converting to spdx-tag-value...
Converting to cyclonedx-json...
Converting to cyclonedx-xml...
✓ Exported to 4 formats in output/rhel-10.0.json/
  output/rhel-10.0.json/rhel-10.0.spdx.json
  output/rhel-10.0.json/rhel-10.0.spdx
  output/rhel-10.0.json/rhel-10.0.cdx.json
  output/rhel-10.0.json/rhel-10.0.cdx.xml
rh-syfter export -p rhel -v 10.0 -f all -o output/  532.54s user 20.74s system 99% cpu 9:14.95 total
```