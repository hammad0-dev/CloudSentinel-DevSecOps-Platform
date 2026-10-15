# Active ZAP 2.17.0 image build specification

The archive dependency closure is verified, but runtime add-on loading and scanner capabilities remain unverified. This is a reproducible build specification, not a claim that the replacement image has been built or runtime-validated.

Use the exact base reference and archive hashes in `backend/config/active-zap-image-manifest.json`. Select exactly one archive for each add-on name (`ascanrules`, `automation`, `network`, and `reports`) only after verifying manifest dependency constraints against ZAP 2.17.0 and the selected archives. Duplicate archives must cause the build gate to fail.

Use `backend/scripts/assemble-zap-image.py` for offline construction. The old Dockerfile template is superseded and must not be built. The assembler uses only Python standard-library archive, hash, and XML processing; it does not call Docker, BuildKit, a frontend, a registry, a package manager, or any network API.

Capture `docker image inspect` and `docker image save` for the exact immutable base reference into a unique directory created with `mktemp -d` under `umask 077`. These commands inspect/export the existing local image; neither builds nor executes it. The assembler validates the exported configuration hash, linux/amd64 platform, non-root user, and all original uncompressed rootfs diff IDs against the independently inspected layer list. It reads layers without extracting filesystem paths or following archive symlinks.

All seven approved archives are read from the effective `/zap/plugin` view. Full hashes, ZIP manifests, minimum ZAP versions, and every required transitive constraint are verified again. Unsupported version/constraint syntax fails closed. Conflicting older versions of the selected add-ons are removed by zero-length `.wh.<filename>` entries. Unrelated base files are preserved. Selected files have mode 0644, UID/GID 0, and remain readable by the original `zap` user.

The output is a Docker-save-compatible archive: `manifest.json`, a SHA-256-named image config JSON, original uncompressed layer tars, and one additional layer. Rootfs diff IDs are SHA-256 values of actual uncompressed tar bytes. Original runtime configuration, environment, entrypoint, user and history are preserved; a deterministic nonempty history entry accompanies the added layer. The assembler validates the resulting config and every layer digest before reporting success. Outer and added tar metadata, JSON serialization, ordering and timestamps are deterministic. Output files are exclusive-created with mode 0600.

Prepare two independent outputs from the same verified export and manifest:

```bash
DAST_ACTIVE_ENABLED=false python3 backend/scripts/assemble-zap-image.py \
  --base "$ZAP_ASSEMBLY_DIR/base.tar" \
  --inspection "$ZAP_ASSEMBLY_DIR/base-inspect.json" \
  --manifest backend/config/active-zap-image-manifest.json \
  --output "$ZAP_ASSEMBLY_DIR/assembly-1.tar" > "$ZAP_ASSEMBLY_DIR/assembly-1.json"
DAST_ACTIVE_ENABLED=false python3 backend/scripts/assemble-zap-image.py \
  --base "$ZAP_ASSEMBLY_DIR/base.tar" \
  --inspection "$ZAP_ASSEMBLY_DIR/base-inspect.json" \
  --manifest backend/config/active-zap-image-manifest.json \
  --output "$ZAP_ASSEMBLY_DIR/assembly-2.tar" > "$ZAP_ASSEMBLY_DIR/assembly-2.json"
cmp "$ZAP_ASSEMBLY_DIR/assembly-1.tar" "$ZAP_ASSEMBLY_DIR/assembly-2.tar"
cmp "$ZAP_ASSEMBLY_DIR/assembly-1.json" "$ZAP_ASSEMBLY_DIR/assembly-2.json"
sha256sum "$ZAP_ASSEMBLY_DIR/assembly-1.tar" "$ZAP_ASSEMBLY_DIR/assembly-2.tar"
```

Only after safety checks and explicit construction authorization, check that the output tag `cloudsentinel/zap-offline:verified-closure` is unused, then use `docker image load --input "$ZAP_ASSEMBLY_DIR/assembly-1.tar"`. Load is a local import, with no build/frontend/registry resolution. Compare the loaded image configuration, RootFS layers and config digest to the assembly record. An offline archive validator is not a substitute for this later engine import check. Never overwrite an unrelated tag. No load or daemon execution occurs automatically in the assembler.

Runtime startup must use a read-only root filesystem with bounded UID/GID-owned tmpfs for ZAP state and `/tmp`, `--network none` for capability validation, loopback API binding, and mandatory API-key authentication. Runtime downloads/updates are forbidden; the assembly preserves base configuration and does not assert that downloads are disabled by configuration alone. Network-disabled validation prevents marketplace access.

Construction requires two byte-identical independent assemblies, final image identity capture, and a non-scanning daemon validation proving all required rule IDs and runtime controls before Active DAST is enabled. Offline dependency verification does not change any production runtime capability gate.
