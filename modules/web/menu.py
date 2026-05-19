from rich.console import Console
from rich.prompt import Prompt
from core.utils import require_project
from modules.web.nuclei import run_nuclei, show_findings

console = Console()


def web_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold cyan]Web Pentest[/bold cyan]")

        console.print(
            "[1] Nuclei — vulnerability scan\n"
            "[2] Показать результаты\n"
            "[0] Назад"
        )

        choice = Prompt.ask(
            "Выберите",
            choices=["1", "2", "0"]
        )

        if choice == "1":
            run_nuclei()
        elif choice == "2":
            show_findings()
        elif choice == "0":
            break
