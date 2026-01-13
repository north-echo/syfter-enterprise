Some notes and observations.

The first obvious different is our SBOM for RHEL 10.0.z is 356MB uncompressed, while Syft generated a 39MB uncompressed file.

## CPE vs PURL

Syft uses CPEs and PURLs while we use PURLs only:

Syft:
``` json
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                ...
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-12.el10_0?arch=x86_64&distro=rhel-10.0&epoch=0&upstream=389-ds-base-3.0.6-12.el10_0.src.rpm"
                }
```

Red Hat:

``` json
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-ppc64le-appstream-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
```

Note that with Syft it uses "upstream=" to denote the source, we have a "repository_id=" to denote... something.  It's also unclear why we are including the source packages in the SBOMs; that may not actually be necessary since customers are installing binaries, not source files.

**TODO**: _is it possible to remove the "arch=" and remove that entirely?  How many packages are exclusive to a single architecture that aren't in others?  Would it make more sense to make these SBOMs arch-specific (and in turn smaller?)_

## Architecture

This is likely where it all explodes.  I'm not sure why it matters to have the same files listed by architecture but apparently we do?  I'm also not wure why Syft duplicates the same CPE so many times.  We'll use `389-ds-base` to compare:

Syft:
``` json
   "packages":
    [
        {
            "name": "389-ds-base",
            "SPDXID": "SPDXRef-Package-rpm-389-ds-base-4779c3cdb619ef50",
            "versionInfo": "0:3.0.6-12.el10_0",
            "supplier": "Organization: Red Hat, Inc.",
            "originator": "Organization: Red Hat, Inc.",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "sourceInfo": "acquired package info from RPM DB: /appstream/os/Packages/3/389-ds-base-3.0.6-12.el10_0.x86_64.rpm",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "(GPL-3.0-or-later WITH GPL-3.0-389-ds-base-exception AND (0BSD OR Apache-2.0 OR MIT) AND (Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT) AND (Apache-2.0 OR BSL-1.0) AND (Apache-2.0 OR LGPL-2.1-or-later OR MIT) AND (Apache-2.0 OR MIT OR Zlib) AND (Apache-2.0 OR MIT) AND (MIT OR Apache-2.0) AND Unicode-3.0 AND (MIT OR Unlicense) AND Apache-2.0 AND MIT AND MPL-2.0 AND Zlib)",
            "copyrightText": "NOASSERTION",
            "externalRefs":
            [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389-ds-base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:redhat:389_ds_base:0\\:3.0.6-12.el10_0:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-12.el10_0?arch=x86_64&distro=rhel-10.0&epoch=0&upstream=389-ds-base-3.0.6-12.el10_0.src.rpm"
                }
            ]
        },
```

Red Hat:
``` json
    {
      "SPDXID": "SPDXRef-6c849a200cf8fc3e0ee30824fa8139580bf4d295fa6e2fac5893a2c48cfae398-pkg-rpm-redhat-389-ds-base-3.0.6-13.el10-0-arch-src",
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-ppc64le-appstream-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-s390x-appstream-e4s-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-s390x-appstream-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-ppc64le-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-aarch64-appstream-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-aarch64-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-x86_64-appstream-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-aarch64-appstream-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-ppc64le-appstream-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-s390x-appstream-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-s390x-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-x86_64-appstream-e4s-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-aarch64-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-s390x-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-x86_64-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-s390x-appstream-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-x86_64-appstream-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-aarch64-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-x86_64-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-ppc64le-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-x86_64-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-ppc64le-appstream-e4s-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-ppc64le-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=codeready-builder-for-rhel-10-s390x-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-aarch64-appstream-source-rpms__10",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-ppc64le-appstream-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-aarch64-appstream-e4s-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src&repository_id=rhel-10-for-x86_64-appstream-eus-source-rpms__10_DOT_0",
          "referenceType": "purl"
        },
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceLocator": "pkg:rpm/redhat/389-ds-base@3.0.6-13.el10_0?arch=src",
          "referenceType": "purl"
        }
      ],
      "filesAnalyzed": false,
      "name": "389-ds-base",
      "supplier": "Organization: Red Hat",
      "versionInfo": "3.0.6-13.el10_0"
    },
```

Interestingly when we pull from the RHEL 10.0 repo (which was mirrored to obtain all the packages), it has all the released versions:

``` bash
$ find /tmp/rhel10.0 -name '389-ds-base-3*'
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-8.el10_0.x86_64.rpm
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-7.el10_0.x86_64.rpm
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-12.el10_0.x86_64.rpm
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-3.el10_0.x86_64.rpm
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-13.el10_0.x86_64.rpm
/tmp/rhel10.0/x86_64/rhsm-pulp.corp.redhat.com/content/dist/rhel10/10.0/x86_64/appstream/os/Packages/3/389-ds-base-3.0.6-5.el10_0.x86_64.rpm
```

## Other TODOs

Syft adds a bogus `documentNamespace` to the Anchore web site that probably needs to be removed and some of the other metadata might need to be adjusted.  The Syft data also includes license information that is pulled from the RPMs, which may be fine to leave in the public SBOMs since it's no real work (although it's possible we could pull that from the Syft export).

Using SQLite locally is definitely faster, but the distributed architecture gives us scale at the expense of speed.  This architecture may not be the best, however, when we have thousands of containers and hundreds of products so there is still some stress-testing to do. If it weren't for file processing (which could be invaluable from an incident response perspective), this would be really fast.