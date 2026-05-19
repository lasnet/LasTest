from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project
from modules.recon.url_discovery import run_passive_url_discovery
from modules.recon.crawling import run_katana, run_katana_aio
from modules.recon.ffuf import run_ffuf_dirs_aio, run_ffuf_dirs

console = Console()

def url_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold yellow]Recon / URL discovery[/bold yellow]")

        console.print(
        "[green]****************************************\n"
        "** gau + waybackurls - passive search **\n"
        "** ffuf - Content discovery           **\n"
        "** katana - Crawling                  **\n"
        "****************************************[/green]\n"
        "* [bold cyan]Recon / URL discovery menu[/bold cyan]\n"
        " * [1] gau + waybackurls\n"
        " * [2] ffuf\n"
        " * [3] katana\n"
        " * [yellow][A] All in one[/yellow]\n"
        "*[bold red] [0] Back[/bold red]\n"
        )

        choice = Prompt.ask(
            "Select",
            choices=["1", "2", "3", "A", "0"]
        )

        if choice == "1":
            run_passive_url_discovery()
            input("Enter...")
        elif choice == "2":
            run_ffuf_dirs()
        elif choice == "3":
            run_katana()
        elif choice == "A":
            run_passive_url_discovery()
            run_ffuf_dirs_aio()
            run_katana_aio()
            input("Enter...")
        elif choice == "0":
            break
