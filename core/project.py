from pathlib import Path
from datetime import datetime
from core.config import save_yaml
from core.project_context import project_context
from rich.console import Console
from rich.prompt import Prompt
from core.scope import scope_domains_menu
from core.scope import scope_ip_menu

PROJECTS_DIR = "projects"
SYSTEM_FILES = {"config.yaml", ".gitkeep"}
console = Console()

def get_project_name():
    if not project_context.active:
        return "No active project"
    return project_context.get("project", "name", default="Unnamed project")

def project_menu():
    while True:
        console.clear()
        console.rule("[bold green]Project management[/bold green]")
        
        name_project = get_project_name()
        console.print(f"[cyan]Open project :[/cyan] [bold green]{name_project}[/bold green]")

        console.print(
            "*[bold cyan] Project menu[/bold cyan]\n"
            " * [1] Create Project\n"
            " * [2] Open Project\n"
            " * [3] Del/Add domain in Project\n"
            " * [4] Del/Add IP in Project\n"
            "* [0] [bold red]Back[/bold red]"
        )

        choice = Prompt.ask(
            "Select",
            choices=["1", "2", "3", "4", "0"]
        )

        if choice == "1":
            create_project()
        elif choice == "2":
            open_project()
        elif choice == "3":
            scope_domains_menu()
        elif choice == "4":
            scope_ip_menu()
        elif choice == "0":
            break

def create_project():
    name = Prompt.ask("[cyan]Enter project name[/cyan]")
    client = Prompt.ask("[cyan]Enter client name[/cyan]")
    description = Prompt.ask("[cyan]Description[/cyan]")
    path = Path(PROJECTS_DIR) / name

    if path.exists():
        console.print("[red]Project already exists[/red]")
        input("Enter...")
        return

    path.mkdir(parents=True)

    for d in ["recon", "web", "osint", "phishing", "reports", "logs"]:
        (path / d).mkdir()

    config = {
        "project": {
            "name": name,
            "client": client,
            "description": description,
            "created_at": datetime.now().strftime("%Y-%m-%d")
        },
        "scope": {
            "domains": [],
            "ips": [],
            "exclusions": []
        }
    }

    save_yaml(path / "config.yaml", config)

    console.print(f"[green]Project {name} created[/green]")
    input("Enter...")

def open_project():
    base = Path(PROJECTS_DIR)

    if not base.exists():
        console.print("[red]No projects directory[/red]")
        input("Enter...")
        return

    projects = sorted([
        p.name for p in base.iterdir()
        if p.is_dir() and p.name not in SYSTEM_FILES and not p.name.startswith(".")
    ])

    if not projects:
        console.print("[red]No projects[/red]")
        input("Enter...")
        return

    console.print("Available projects:")
    indexed_projects = {str(idx): name for idx, name in enumerate(projects, start=1)}
    for idx, name in indexed_projects.items():
        console.print(f"[cyan][{idx}][/cyan] - {name}")

    selected_idx = Prompt.ask("Enter project number", choices=list(indexed_projects.keys()))
    selected = indexed_projects[selected_idx]

    path = base / selected
    project_context.load(path)
