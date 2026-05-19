from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project

console = Console()

def osint_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold magenta]OSINT[/bold magenta]")

        console.print(
            "[1] (позже)\n"
            "[0] Назад"
        )

        choice = Prompt.ask("Выберите", choices=["1", "0"])

        if choice == "0":
            break
        else:
            console.print("[yellow]Модуль в разработке[/yellow]")
            input("Enter...")
