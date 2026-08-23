# Vendored: Windows Log Threat Hunter

This is a **copy**, not the original. The project lives at
[barisburakturgut/windows-log-threat-hunter](https://github.com/barisburakturgut/windows-log-threat-hunter)
and that is the version to file issues against or send changes to.

## Why it is here

The triage engine scores findings; it does not produce them. That is stage 1's
job, and stage 1 is a separate project. Requiring people to clone two
repositories before anything happens made the launcher's "Scan this PC" option
fail for the most common case of all: someone who downloaded this repo as a ZIP.

So a snapshot rides along. The launcher still prefers a real copy wherever it
finds one, whether that is a clone beside this folder or `THREAT_HUNTER` pointing
at a script, and falls back here only when there is nothing else. Edit the real
repository, not this folder.

## What this means

The snapshot drifts. It was taken on **23 August 2026** and will not pick up
later fixes to the upstream project on its own. If a scan behaves differently
here than it does when you run the real thing, the real thing is right.

## License

Same author, same MIT terms as the rest of this repository. The `LICENSE` file
beside this one is the upstream project's own copy.

Baris Burak Turgut
