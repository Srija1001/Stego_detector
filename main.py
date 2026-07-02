"""
Steganography Detector - Main Entry Point
"""
import sys
import os

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import App

if __name__ == "__main__":
    app = App()
    app.mainloop()
