from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project

console = Console()

def phishing_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold red]Phishing (restricted)[/bold red]")

        console.print(
            "[!] Модуль отключён по умолчанию\n"
            "[0] Назад"
        )

        choice = Prompt.ask("Выберите", choices=["0"])

        if choice == "0":
            break
