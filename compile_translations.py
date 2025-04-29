#!/usr/bin/env python3
"""
Compile translation files for the Flask application.
This script compiles all .po files in the translations directory to .mo files.
"""

import os
import subprocess
import glob

def compile_translations():
    """
    Compile all .po files to .mo files using pybabel.
    """
    print("Compiling translation files...")
    
    # Check for all language directories
    language_dirs = glob.glob("translations/*/LC_MESSAGES")
    
    if not language_dirs:
        print("No language directories found in translations/")
        return
    
    for lang_dir in language_dirs:
        lang = lang_dir.split(os.path.sep)[1]
        po_file = os.path.join(lang_dir, "messages.po")
        
        if not os.path.exists(po_file):
            print(f"Warning: No messages.po file found for language '{lang}'")
            continue
        
        print(f"Compiling translations for '{lang}'...")
        try:
            subprocess.run(
                ["pybabel", "compile", "-d", "translations", "-l", lang],
                check=True
            )
            print(f"Successfully compiled translations for '{lang}'")
        except subprocess.CalledProcessError as e:
            print(f"Error compiling translations for '{lang}': {e}")
        except FileNotFoundError:
            print("Error: pybabel command not found. Make sure Flask-Babel is installed.")
            print("Try running: pip install Flask-Babel")
            return

if __name__ == "__main__":
    compile_translations()
    print("Done!") 