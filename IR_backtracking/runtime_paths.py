import os
import sys


def resource_path(relative_path: str) -> str:
    """
    Resolve resource path for both source execution and PyInstaller EXE.
    """
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
