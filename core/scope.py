from rich.console import Console
from rich.prompt import Prompt, Confirm
from core.project_context import project_context

console = Console()


def scope_domains_menu():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    while True:
        console.clear()
        console.rule("[bold green]Scope / Domains[/bold green]")

        domains = project_context.get("scope", "domains", default=[])
        
        name_project = project_context.get("project", "name")
        console.print(f"[cyan]Open project :[/cyan] [bold green]{name_project}[/bold green]")

        if domains:
            console.print("[cyan]Current domains:[/cyan]")
            for d in domains:
                console.print(f" - {d}")
        else:
            console.print("[yellow]The list of domains is empty[/yellow]")

        console.print(
            "\n* [1] Add domain\n"
            "* [2] Del domain\n"
            "* [3] Clear list\n"
            "* [bold red][0] Back[/bold red]\n"
        )

        choice = Prompt.ask("Select", choices=["1", "2", "3", "0"])

        if choice == "1":
            add_domain(domains)
        elif choice == "2":
            remove_domain(domains)
        elif choice == "3":
            clear_domains()
        elif choice == "0":
            break


def add_domain(domains: list):
    domain = Prompt.ask("Enter domain (example.com)").strip().lower()

    if domain in domains:
        console.print("[yellow]Domain is already in scope[/yellow]")
        input("Enter...")
        return

    domains.append(domain)
    project_context.set(sorted(domains), "scope", "domains")

    console.print(f"[green]Domain {domain} added[/green]")
    input("Enter...")


def remove_domain(domains: list):
    if not domains:
        console.print("[yellow]List is empty[/yellow]")
        input("Enter...")
        return

    domain = Prompt.ask("Enter domain for delete").strip().lower()

    if domain not in domains:
        console.print("[red]Domain not found[/red]")
        input("Enter...")
        return

    domains.remove(domain)
    project_context.set(sorted(domains), "scope", "domains")

    console.print(f"[green]Domain {domain} deleted[/green]")
    input("Enter...")


def clear_domains():
    confirm = Confirm.ask(
        "[red]Are you sure you want to delete ALL the domains??[/red]"
    )

    if confirm:
        project_context.set([], "scope", "domains")
        console.print("[green]Scope domains clear[/green]")
        input("Enter...")

########################################################################

def scope_ip_menu():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    while True:
        console.clear()
        console.rule("[bold green]Scope / IPs[/bold green]")

        ips = project_context.get("scope", "ips", default=[])
        
        name_project = project_context.get("project", "name")
        console.print(f"[cyan]Open project :[/cyan] [bold green]{name_project}[/bold green]")

        if ips:
            console.print("[cyan]Current ips:[/cyan]")
            for d in ips:
                console.print(f" - {d}")
        else:
            console.print("[yellow]The list of ips is empty[/yellow]")

        console.print(
            "\n* [1] Add IPs\n"
            "* [2] Del IPs\n"
            "* [3] Clear list\n"
            "* [bold red][0] Back[/bold red]\n"
        )

        choice = Prompt.ask("Select", choices=["1", "2", "3", "0"])

        if choice == "1":
            add_ip(ips)
        elif choice == "2":
            remove_ip(ips)
        elif choice == "3":
            clear_ip()
        elif choice == "0":
            break


def add_ip(ips: list):
    ip = Prompt.ask("Enter IP (10.10.10.10)").strip().lower()

    if ip in ips:
        console.print("[yellow]IP is already in scope[/yellow]")
        input("Enter...")
        return

    ips.append(ip)
    project_context.set(sorted(ips), "scope", "ips")

    console.print(f"[green]IP {ip} added[/green]")
    input("Enter...")


def remove_ip(ips: list):
    if not ips:
        console.print("[yellow]List is empty[/yellow]")
        input("Enter...")
        return

    ip = Prompt.ask("Enter IP for delete").strip().lower()

    if ip not in ips:
        console.print("[red]IP not found[/red]")
        input("Enter...")
        return

    ips.remove(ip)
    project_context.set(sorted(ips), "scope", "ips")

    console.print(f"[green]IP {ip} deleted[/green]")
    input("Enter...")


def clear_ip():
    confirm = Confirm.ask(
        "[red]Are you sure you want to delete ALL the IPs??[/red]"
    )

    if confirm:
        project_context.set([], "scope", "ips")
        console.print("[green]Scope IPs clear[/green]")
        input("Enter...")
