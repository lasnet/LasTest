from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project
from modules.recon.subdomains import subdomains_menu
from modules.recon.http_probe import show_alive_hosts
from modules.recon.httpx_url_mode import run_httpx_url_mode
from modules.recon.nmap import nmap_menu
from modules.recon.url_menu import url_menu
from modules.recon.targets_url_normalize import run_targets_url_normalize
from modules.recon.targets_tech_routing import run_targets_tech_routing

console = Console()

def recon_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold yellow]Recon[/bold yellow]")

        console.print(
        "* [bold cyan]Recon menu[/bold cyan]\n"
        " * [1] Subdomains discovery\n"
        " * [2] URL discovery\n"
        " * [3] URL availability\n"
        " * [4] Nmap\n"
        "* [bold cyan]Report[/bold cyan]\n"
        " * [01] View probing Subdomains\n"
        "*[bold red] [0] Back[/bold red]\n"
        )

        choice = Prompt.ask(
            "Choose",
            choices=["1", "2", "3", "4", "01", "0"]
        )

        if choice == "1":
            subdomains_menu()
        elif choice == "2":
            url_menu()
        elif choice == "3":
            console.print(
            "* [bold cyan]URL availability menu[/bold cyan]\n"
            " * [1] Normalize URLs\n"
            " * [2] HTTPX Enrich\n"
            " * [3] Tech routing\n"
            " * [bold yellow][A] All in one[/bold yellow]\n"
            "*[bold red] [0] Back[/bold red]\n"
            )
            choice = Prompt.ask(
                "Choose",
                choices=["1", "2", "3", "A", "0"]
            )
            if choice == "1":
                run_targets_url_normalize()
                input("Enter...")
            elif choice == "2":
                run_httpx_url_mode()
                input("Enter...")
            elif choice == "3":
                run_targets_tech_routing()
                input("Enter...")
            elif choice == "A":
                run_targets_url_normalize()
                run_httpx_url_mode()
                run_targets_tech_routing()
                input("Enter...")
            elif choice == "0":
                break
        elif choice == "4":
            nmap_menu()
        elif choice == "01":
            show_alive_hosts()
        elif choice == "0":
            break
