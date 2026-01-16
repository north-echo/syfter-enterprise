# Understanding Multi-Stage Container Builds in Syfter

This document explains how syfter handles multi-stage Docker/Podman builds and why
you may see fewer layers than expected when scanning certain containers.

## What Are Multi-Stage Builds?

Multi-stage builds are a Docker feature that allows you to use multiple `FROM`
statements in a single Containerfile. Each `FROM` instruction starts a new build
stage, and only the **final stage** ends up in the resulting image.

This is commonly used to:
- Keep final images small (no build tools)
- Separate build-time dependencies from runtime dependencies
- Compile code in one stage, copy only the binaries to the final stage

## Real-World Example: konflux-ci/task-runner

Consider this Containerfile from [konflux-ci/task-runner](https://github.com/konflux-ci/task-runner/blob/main/Containerfile):

```dockerfile
# Stage 1: Build stage using go-toolset
FROM registry.access.redhat.com/ubi10/go-toolset:1.25.3@sha256:... AS go-build

USER 0
WORKDIR /deps/golang/tools
COPY deps/go-tools/ .
RUN GOBIN=/deps/golang/bin ./install-tools.sh

WORKDIR /repo
COPY . .
RUN cd deps/go-submodules && \
    GOBIN=/deps/golang/bin ./install-submodules.sh


# Stage 2: Final runtime image using ubi-minimal
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.1-1766033715@sha256:...

# Copy ONLY the compiled binaries from stage 1
COPY --from=go-build /deps/golang/bin/ /usr/local/bin/

# ... rest of final image setup ...
```

### What Syfter Shows

When you scan this container:

```bash
$ syfter scan quay.io/konflux-ci/task-runner:1.1.1 -p konflux-task-runner -v 1.1.1
```

And view the layers:

```bash
$ syfter layers -p konflux-task-runner -v 1.1.1
╭─────────────────────────── Container Layer Chain ────────────────────────────╮
│ Container: quay.io/konflux-ci/task-runner:1.1.1                              │
│ Layers: 2                                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯

  #   Layer ID        Source Image        Version   Image Reference
 ─────────────────────────────────────────────────────────────────────────────
  0   df553b0643bb8   ubi10/ubi-minimal   10.1      ubi10/ubi-minimal:10.1-...
  1   680577dd65291   ubi10/ubi-minimal   10.1      ubi10/ubi-minimal:10.1-...

Unique source images: 1
  • ubi10/ubi-minimal
```

**You only see `ubi-minimal` layers - no `go-toolset`!**

### Why This Is Correct

This is expected behavior:

| What Happened | In Final Image? |
|---------------|-----------------|
| `go-toolset` image layers | ❌ No - discarded after build |
| Go compiler, build tools | ❌ No - only in build stage |
| RPMs from `go-toolset` | ❌ No - not in final image |
| Compiled Go binaries | ✅ Yes - copied via `COPY --from` |
| `ubi-minimal` base layers | ✅ Yes - this is the actual base |

The `go-toolset` image was used purely as a build environment. Its layers are
completely excluded from the final image. Only the **files** produced during
the build (compiled binaries) are copied to the final image.

## Understanding Package Detection

### RPM Packages

When you search for packages, you'll only find what's actually installed in the
final image:

```bash
$ syfter query -p konflux-task-runner -v 1.1.1 -n '%gcc%'
No packages found
```

No GCC! Even though `go-toolset` includes GCC for cgo compilation, it's not in
the final image because the entire `go-toolset` stage was discarded.

### Go Modules

However, you may see Go-related packages:

```bash
$ syfter query -p konflux-task-runner -v 1.1.1 -n '%golang%'
❯ syfter query -p konflux-task-runner -v 1.1.1 -n '%golang%'    
                                                            Package Search Results                                                            
                                                                                                                                              
  Name                                                  Version                                Product                     Source Image       
 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 
  github.com/golang-jwt/jwt/v4                          v4.5.2                                 konflux-task-runner-1.1.1   ubi10/ubi-minimal  
  github.com/golang-jwt/jwt/v5                          v5.3.0                                 konflux-task-runner-1.1.1   ubi10/ubi-minimal  
  ...
```

These are **Go modules**, not installed software. Syft analyzes compiled Go
binaries and extracts the module dependencies that were compiled into them.
These represent the Go libraries used in the source code, detected from the
binary metadata.

### File Searches

```bash
$ syfter query -p konflux-task-runner -v 1.1.1 -f '/usr/local/bin/%'
No files found
```

**Why no results?** The file search queries files tracked by **package managers**
(RPM manifests, npm package contents, etc.). The binaries in `/usr/local/bin/`
were copied directly - they're not tracked by any package manager, so they don't
appear in the file index.

This is a limitation of SBOM-based file tracking: it only knows about files that
were installed via a package manager.

## Key Takeaways

1. **Multi-stage builds produce lean images**: Only the final `FROM` stage's
   layers are included. Build tools are discarded.

2. **Syfter shows the truth**: When you see only `ubi-minimal` layers, it means
   that's genuinely the only base image in the final container.

3. **Copied files vs. installed packages**: Files copied via `COPY --from` are
   in the image but not tracked by package managers. They won't appear in file
   searches.

4. **Go module detection**: Syft extracts Go module information from compiled
   binaries. These appear as packages even though they weren't "installed" -
   they were compiled into the binary.

5. **Security benefits**: Multi-stage builds reduce attack surface. The final
   image doesn't contain compilers, build tools, or source code - just the
   runtime requirements.

## Verifying Build Stages

If you need to understand what was used during the build (not what's in the
final image), you have a few options:

1. **Review the Containerfile/Dockerfile**: This shows the complete build process
2. **Check build logs**: CI/CD systems often retain build logs
3. **Examine image labels**: Some builds embed provenance information in labels

```bash
# Pull the image first (required for inspect)
podman pull quay.io/konflux-ci/task-runner:1.1.1

# Check if the image has build metadata labels
podman inspect quay.io/konflux-ci/task-runner:1.1.1 | jq '.[0].Config.Labels'
```

Alternatively, use `skopeo` to inspect remote images without pulling:

```bash
# Inspect remote image labels without pulling
skopeo inspect docker://quay.io/konflux-ci/task-runner:1.1.1 | jq '.Labels'

# On Mac (arm64), if the image is only built for amd64/linux:
skopeo inspect --override-arch amd64 --override-os linux \
  docker://quay.io/konflux-ci/task-runner:1.1.1 | jq '.Labels'
```

## Summary

When scanning multi-stage build containers:

| You Expect | You See | Why |
|------------|---------|-----|
| `go-toolset` layer | Not present | Build stage discarded |
| Go compiler packages | Not present | Only in build stage |
| Go module packages | Present | Detected in compiled binaries |
| Copied binaries | Present (but not in file search) | Not package-managed |
| `ubi-minimal` base | Present | Actual runtime base |

This is syfter working correctly - it shows what's **actually** in the final
container, not what was used to build it.
