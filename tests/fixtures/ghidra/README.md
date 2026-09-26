# Ghidra exercise input

`WinHelloCPP.exe` is the benign 32-bit Windows PE from Ghidra's class exercises,
copied unchanged from the Ghidra 12.1.4 public distribution:

```text
docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe
```

- Size: 110,592 bytes
- SHA-256: `7a98a934de5f578c3a547af873221b221d037bafa87ceee71dd4f089dd228202`
- Origin: Ghidra (National Security Agency)
- License: [Apache License 2.0](LICENSE), as supplied with Ghidra. The corresponding
  source is in the distribution's adjacent `WinhelloCPP/source/` directory and
  carries the `IP: GHIDRA` Apache 2.0 notice.

The runtime tests import and analyze this file through Ghidra; they do not launch
the Windows executable. Keeping it in this directory allows fresh clones and
worktrees to run those tests without copying anything from the ignored `samples/`
directory or relying on exercise files in the installed Ghidra.
