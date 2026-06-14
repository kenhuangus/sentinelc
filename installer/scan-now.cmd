@echo off
REM Trigger an on-demand SentinelC scan. The task already runs as SYSTEM,
REM so this does NOT prompt for UAC. Safe to call from a tray app or shortcut.
schtasks /run /tn "\SentinelC\FullScan"
