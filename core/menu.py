from rich.console import Console
from rich.prompt import Prompt
from core.project import project_menu
from modules.recon.menu import recon_menu
from modules.web.menu import web_menu
from modules.osint.menu import osint_menu
from modules.phishing.menu import phishing_menu
from modules.reports.menu import reports_menu


console = Console()

def main_menu():
    while True:
        console.clear()
        console.rule("[bold cyan]Pentest Platform[/bold cyan]")
        console.rule("[bold cyan]LasTest v 1.2[/bold cyan]")

        console.print(
            "*[bold cyan] Main menu[/bold cyan]\n"
            " * [1] Project management\n"
            " * [2] Recon / Enumeration\n"
            " * [3] Web Pentest\n"
            " * [4] OSINT\n"
            " * [5] Phishing (restricted)\n"
            " * [6] Reports\n"
            "* [bold red][0] Quit[/bold red]\n"
        )

        choice = Prompt.ask("Select", choices=["1","2","3","4","5", "6", "0"])

        if choice == "1":
            project_menu()
        elif choice == "2":
            recon_menu()
        elif choice == "3":
            web_menu()
        elif choice == "4":
            osint_menu()
        elif choice == "5":
            phishing_menu()
        elif choice == "6":
            reports_menu()
        elif choice == "0":
            console.print("Quit.")
            break
