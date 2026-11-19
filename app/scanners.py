"""Locate the external scanners installed in the image."""
import os
import shutil


NAMES = ("ffuf", "nuclei", "sqlmap", "zap-baseline.py")


def scanner_paths():
    return {name: shutil.which(name) for name in NAMES}


def missing():
    return [name for name, path in scanner_paths().items() if not path]


def templates_dir():
    path = os.environ.get("CHARTER_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    return path if os.path.isdir(path) else ""
