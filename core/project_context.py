from pathlib import Path
from core.config import load_yaml, save_yaml
from rich.console import Console

console = Console()

class ProjectContext:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.active = False
        return cls._instance

    def load(self, project_path: Path):
        self.path = project_path
        self.config_path = project_path / "config.yaml"
        self.config = load_yaml(self.config_path)
        self.active = True

        console.print(
            f"[green]Активный проект:[/green] {self.config.get('project', {}).get('name')}"
        )

    def save(self):
        if not self.active:
            return
        save_yaml(self.config_path, self.config)

    def get(self, *keys, default=None):
        data = self.config
        for k in keys:
            data = data.get(k, {})
        return data or default

    def set(self, value, *keys):
        data = self.config
        for k in keys[:-1]:
            data = data.setdefault(k, {})
        data[keys[-1]] = value
        self.save()

project_context = ProjectContext()
