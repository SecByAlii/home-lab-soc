# Sysmon configuration on the Windows victim (win01)

The Windows detections (12, 13, 15) rely on [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
for the telemetry that the Windows Security log doesn't provide — registry writes, process
command lines, and process-access handles. This note records how Sysmon is set up on
`win01` and the one tuning change the detections required, the same way
[`audit-rules/`](audit-rules/) documents the Linux `auditd` setup.

## Base config

- **Binary:** `Sysmon64a.exe` — the **ARM64** build of Sysmon (win01 is Windows 11 on Arm).
  Signature verified as *Microsoft Windows Publisher* before install.
- **Config:** [SwiftOnSecurity `sysmonconfig-export.xml`](https://github.com/SwiftOnSecurity/sysmon-config),
  the community baseline. It gives good process-creation (event 1) and registry (event 13)
  coverage out of the box, which detections 11, 12, and 13 use as-is.

## The one change: enable ProcessAccess for detection 15

The SwiftOnSecurity config ships **ProcessAccess (event 10) disabled** — the section is an
empty `include` block, which by Sysmon's rules logs nothing:

```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <!-- Using "include" with no rules means nothing in this section will be logged -->
    </ProcessAccess>
</RuleGroup>
```

This is a deliberate default: on a busy host, handle opens to LSASS are frequent and noisy.
Detecting LSASS credential-dump access (detection 15) requires turning it on and scoping it
to the process that matters:

```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <!-- Detection 15 (T1003.001): catch handles opened to LSASS -->
        <TargetImage condition="image">lsass.exe</TargetImage>
    </ProcessAccess>
</RuleGroup>
```

Apply with `Sysmon64a.exe -c sysmonconfig.xml`. This logs **every** access to `lsass.exe`;
the filtering to dump-grade access masks happens in the detection SPL, not in Sysmon — so
the benign `svchost → lsass 0x1000` baseline is still collected but excluded at search time.
That split (collect broadly on a scoped target, filter in detection) is the SwiftOnSecurity
philosophy for ProcessAccess and keeps the config simple.

## Note on event format

The Sysmon input on the forwarder is set to **`renderXml = false`** (classic key-value
rendering) rather than XML. On a bare indexer with no Splunk Add-on for Windows, classic
rendering is what makes `EventCode`, `CommandLine`, `TargetObject`, and `GrantedAccess`
auto-extract as fields — keeping the Sysmon SPL consistent with the Security-log detections.
See [`../setup/04-windows-victim.md`](../setup/04-windows-victim.md).
