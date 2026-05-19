from core.project_context import project_context
from core.project import project_menu
from rich.console import Console

console = Console()

def require_project():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        project_menu()
        return False
    return True
