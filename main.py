"""
main.py
-------
Entry point for Iffy Offer.

Just creates the Tkinter root window and hands control to the App class.
Keeping this file minimal means it's easy to swap the GUI toolkit later
without touching the application logic.
"""

import tkinter as tk
from gui import IffyOfferApp


def main():
    root = tk.Tk()
    app  = IffyOfferApp(root)
    app.run()


if __name__ == '__main__':
    main()
