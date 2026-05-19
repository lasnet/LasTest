#!/usr/bin/env python3

from core.menu import main_menu
from core.logger import init_logger

def main():
    init_logger()
    main_menu()

if __name__ == "__main__":
    main()
