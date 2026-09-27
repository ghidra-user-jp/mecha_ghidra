"""The Ghidra GUI backend (``--backend gui``): Ghidra's own GUI owns the project and every program.

The rest of ``ghidra_headless`` runs unchanged against the programs the GUI's
``ProgramManager`` opened; this package holds what differs: starting the GUI
(``launch``), the project handle that borrows the GUI's project and programs
(``project_handle``), work on Swing's event dispatch thread (``edt``) and the
startup checks run while the GUI comes up (``readiness``).
"""
