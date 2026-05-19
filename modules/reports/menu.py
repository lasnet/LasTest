from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project
from modules.reports.subdomains_enrich import run_subdomains_enrich_report

console = Console()

def reports_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold yellow]Reports[/bold yellow]")

        console.print(
            "* [bold cyan]Reports menu[/bold cyan]\n"
            " * [1] Subdomains reports\n"
            "* [bold red][0] Back[/bold red]\n"
        )

        choice = Prompt.ask("Choose", choices=["1", "0"])

        if choice == "1":
            run_subdomains_enrich_report()
            input("Enter...")
        elif choice == "0":
            break
