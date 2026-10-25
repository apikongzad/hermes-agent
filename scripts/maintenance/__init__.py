"""Standalone maintenance controller for Hermes runtime cutover.

Root-owned, stdlib-only: never import mutable user modules (pm, hermes_cli,
gateway). All effects go through the injected Host adapter so tests exercise
the actual orchestrator with a fake filesystem/process/network.
"""
