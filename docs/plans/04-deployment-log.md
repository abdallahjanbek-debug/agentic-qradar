# Deployment Log — first install attempt

Date: 2026-08-17
Target: `192.168.8.202` (janbek-qradar.local) — local test console
Outcome: **not installed.** Package upload rejected; cause not yet identified.

---

## 1. Console facts discovered

Established by querying the live console with an admin authorized-service token.

| Fact | Value |
|---|---|
| QRadar version | 7.5.0 UpdatePackage 14 (build 2021.6.14.20251017194912) |
| Highest non-deprecated API version | **27.0** (`20.0` is present but **deprecated**) |
| Base image used by all installed apps | **`qradar-app-base:4.0.9`** |
| Installed apps | 1051 IBM QRadar Hub (CREATING), 1052 Log Source Management (RUNNING), 1053 Pulse (RUNNING) |
| App memory already allocated | **1050 MB** (600 + 100 + 350) |
| Console total memory | Not exposed via `/api/system/servers` — could not verify the 10% cap |
| **Offenses on the console** | **0** — `items */0` for OPEN, CLOSED, and HIDDEN |
| Certificate | Self-signed; calls made with verification disabled |

Reachability was confirmed first: ICMP 2/2, HTTPS 443 → 200, and an unauthenticated
`/api/help/versions` returning QRadar's characteristic `SEC` header 401.

---

## 2. Changes made as a result

Three planning assumptions were wrong against this console and were corrected
before packaging:

| File | Was | Now | Why |
|---|---|---|---|
| `app/config.py` | `QRADAR_API_VERSION = "20.0"` | `"27.0"` | 20.0 is deprecated here. 27.0 verified working against `/siem/offenses`. |
| `manifest.json` | `qradar-app-base:2.0.0` | `qradar-app-base:4.0.9` | Every app on this console uses 4.0.9; 2.0.0 presence unverified. |
| `manifest.json` | `"resources": 1024` | `"resources": 512` | 1050 MB already allocated. The 10%-of-console cap could not be verified via API, so 1024 risked exceeding it. |
| `app/config.py` | `worker_concurrency: 4` | `2` | Matches the reduced memory. Design target of 4 stands for production — see `01-offense-ingestion.md` §8. |

Confirmed the code contains **no f-strings**, so it runs on whatever Python the
4.0.9 base image ships.

---

## 3. Packaging

The QRadar App SDK (`qapp`) is **not installed and cannot be installed here**:

- Not on PyPI (all three plausible package names return no distribution).
- Distributed as a zip from IBM X-Force App Exchange, behind an IBM login.
- On Windows it requires WSL with a real Linux distro; only `docker-desktop`
  (Docker Desktop's utility VM) is registered.

Packaging was done without it:

- **Dependencies vendored** as Linux wheels via `pip download --platform
  manylinux2014_x86_64` for both cp39 and cp311, covering whichever Python the
  base image uses. The compiled ones that matter are `pydantic-core` and `jiter`;
  everything else is `py3-none-any`. Total 6.9 MB in `container/pip/`.
- **Manifest validated** (required fields, RFC-4122 uuid, unique service names,
  areas/config pages carrying id + url) — replicating what `qapp package` checks.
- **Zip built** with Python `zipfile`: 44 files, 7.0 MB.

---

## 4. The failure

`POST /api/gui_app_framework/application_creation_task` returned:

```
HTTP 500
code 33101 — "An error occurred while reading the application zip file."
message  — "An error occurred while reading zip file /storetmp/AppFW_1054.zip"
```

Attempts created task IDs **1054, 1057, 1058** — these may be lingering on the
console and worth cleaning up.

### What was ruled out

| Hypothesis | Test | Result |
|---|---|---|
| Transfer truncation | `-w %{size_upload}` | All 6,997,566 bytes arrived. Not a transfer problem. |
| Corrupt local archive | `zipfile.testzip()`, magic bytes | Clean. `PK\x03\x04`, 44 entries, manifest readable. |
| Size / `/storetmp` disk space | Re-uploaded a 29,523-byte build with the wheels removed | **Failed identically.** Not size-related. |

So the upload succeeds, the console writes the file, and then fails to read it as
a zip — pointing at an archive-format or request-format mismatch rather than
anything environmental.

### Not yet tested (next steps)

1. **`multipart/form-data`** (`curl -F "file=@socai.zip"`) instead of a raw body —
   the most likely candidate.
2. **Omitting the `Version` header** — the endpoint is documented against API 17.0;
   sending `Version: 27.0` may route it oddly. It did return an app-framework
   error code (33101), so it reached the right handler, but this is cheap to rule out.
3. **`Content-Type: application/octet-stream`** instead of `application/zip`.
4. **Explicit directory entries in the zip** — Python's `zipfile` writes only file
   entries. A stream-based Java reader on the QRadar side may expect directory
   entries present.
5. **Console-side logs** — `/var/log/qradar.log` on the console will contain the
   actual Java stack trace behind error 33101, which would settle this immediately.
   That is the highest-value next step and needs shell access to the console.

---

## 5. Separate blocker: no offenses exist

The console reports **zero offenses** in every status. Even once the app installs,
there is nothing for it to investigate. The ingest path (poll, watermark advance,
no crash on an empty result) can be verified, and so can the settings page and
connectivity diagnostics — but the investigation path, the LLM call, and the
output contract cannot be exercised until offenses exist.

Options, not yet decided:

- Generate log activity that trips existing rules.
- Create a permissive custom rule that fires on any event.
- Inject synthetic offenses.

---

## 6. State at stop

- Code and docs complete and committed to the working tree (staged, **not
  committed to git**).
- `socai.zip` and `socai-min.zip` exist in the repo root; both are gitignored.
- Vendored wheels in `container/pip/`; gitignored as build artifacts.
- Nothing was installed on the console. No console state was modified beyond the
  three failed creation tasks.
- The QRadar token was stored outside the repo, in the session scratchpad.
