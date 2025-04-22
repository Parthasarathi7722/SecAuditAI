"""
Interactive TUI for SecAuditAI.
"""
import inquirer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Dict, Any, List, Optional
from .plugins import PluginManager
from .config import ConfigManager
from .ai import AIManager

console = Console()

class TUI:
    """Interactive Text User Interface for SecAuditAI."""
    
    def __init__(self):
        self.plugin_manager = PluginManager()
        self.config_manager = ConfigManager()
        self.ai_manager = AIManager(self.config_manager.get_config().ai.dict())

    def show_main_menu(self) -> None:
        """Display the main menu."""
        while True:
            questions = [
                inquirer.List(
                    'action',
                    message="What would you like to do?",
                    choices=[
                        'Run Security Scan',
                        'Configure Settings',
                        'Manage AI Models',
                        'View Reports',
                        'Exit'
                    ]
                )
            ]
            answers = inquirer.prompt(questions)
            
            if not answers:
                break
                
            action = answers['action']
            if action == 'Run Security Scan':
                self.run_scan_menu()
            elif action == 'Configure Settings':
                self.config_menu()
            elif action == 'Manage AI Models':
                self.ai_menu()
            elif action == 'View Reports':
                self.reports_menu()
            elif action == 'Exit':
                break

    def run_scan_menu(self) -> None:
        """Display scan options menu."""
        questions = [
            inquirer.List(
                'scan_type',
                message="Select scan type",
                choices=[
                    'Cloud Infrastructure',
                    'Code Analysis',
                    'Container Security',
                    'SBOM Analysis',
                    'Back'
                ]
            )
        ]
        answers = inquirer.prompt(questions)
        
        if not answers:
            return
            
        scan_type = answers['scan_type']
        if scan_type == 'Cloud Infrastructure':
            self.cloud_scan_menu()
        elif scan_type == 'Code Analysis':
            self.code_scan_menu()
        elif scan_type == 'Container Security':
            self.container_scan_menu()
        elif scan_type == 'SBOM Analysis':
            self.sbom_scan_menu()

    def cloud_scan_menu(self) -> None:
        """Display cloud scanning options."""
        questions = [
            inquirer.List(
                'cloud_provider',
                message="Select cloud provider",
                choices=['AWS', 'Azure', 'GCP', 'Kubernetes', 'Back']
            )
        ]
        answers = inquirer.prompt(questions)
        
        if not answers or answers['cloud_provider'] == 'Back':
            return
            
        provider = answers['cloud_provider'].lower()
        if provider == 'kubernetes':
            self.kubernetes_scan_menu()
        else:
            self.run_cloud_scan(provider)

    def run_cloud_scan(self, provider: str) -> None:
        """Run cloud infrastructure scan."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {provider.upper()} infrastructure...", total=None)
            
            try:
                plugin = self.plugin_manager.get_plugin(provider)
                if plugin:
                    config = self.config_manager.get_config().cloud.dict()
                    results = plugin.scan(target=provider, **config)
                    
                    # Display results
                    self.display_scan_results(results)
                else:
                    console.print(f"[red]No scanner plugin found for {provider}[/red]")
            except Exception as e:
                console.print(f"[red]Error during scan: {str(e)}[/red]")

    def display_scan_results(self, results: Dict[str, Any]) -> None:
        """Display scan results in a formatted table."""
        table = Table(title="Scan Results")
        table.add_column("Resource", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Message", style="white")
        
        for finding in results.get('findings', []):
            status_color = {
                'failed': 'red',
                'passed': 'green',
                'error': 'yellow'
            }.get(finding['status'], 'white')
            
            table.add_row(
                finding['resource'],
                f"[{status_color}]{finding['status']}[/{status_color}]",
                finding['message']
            )
        
        console.print(table)
        
        # Show summary
        summary = results.get('summary', {})
        console.print(Panel(
            f"Total Findings: {summary.get('total', 0)}\n"
            f"Failed: {summary.get('failed', 0)}\n"
            f"Passed: {summary.get('passed', 0)}\n"
            f"Errors: {summary.get('error', 0)}",
            title="Summary"
        ))

    def config_menu(self) -> None:
        """Display configuration options."""
        questions = [
            inquirer.List(
                'config_section',
                message="Select configuration section",
                choices=['Cloud', 'AI', 'Scanner', 'Back']
            )
        ]
        answers = inquirer.prompt(questions)
        
        if not answers or answers['config_section'] == 'Back':
            return
            
        section = answers['config_section'].lower()
        if section == 'cloud':
            self.cloud_config_menu()
        elif section == 'ai':
            self.ai_config_menu()
        elif section == 'scanner':
            self.scanner_config_menu()

    def cloud_config_menu(self) -> None:
        """Configure cloud settings."""
        config = self.config_manager.get_config().cloud.dict()
        
        questions = [
            inquirer.Text('aws_profile', message="AWS Profile", default=config.get('aws_profile')),
            inquirer.Text('aws_region', message="AWS Region", default=config.get('aws_region')),
            inquirer.Text('azure_subscription', message="Azure Subscription ID", default=config.get('azure_subscription')),
            inquirer.Text('gcp_project', message="GCP Project ID", default=config.get('gcp_project'))
        ]
        
        answers = inquirer.prompt(questions)
        if answers:
            self.config_manager.update_config({'cloud': answers})

    def ai_config_menu(self) -> None:
        """Configure AI settings."""
        config = self.config_manager.get_config().ai.dict()
        
        questions = [
            inquirer.Text('model_name', message="Model Name", default=config.get('model_name')),
            inquirer.Text('cache_dir', message="Cache Directory", default=config.get('cache_dir')),
            inquirer.Text('max_tokens', message="Max Tokens", default=str(config.get('max_tokens'))),
            inquirer.Text('temperature', message="Temperature", default=str(config.get('temperature')))
        ]
        
        answers = inquirer.prompt(questions)
        if answers:
            # Convert string inputs to appropriate types
            answers['max_tokens'] = int(answers['max_tokens'])
            answers['temperature'] = float(answers['temperature'])
            self.config_manager.update_config({'ai': answers})

    def run(self) -> None:
        """Start the TUI."""
        console.print(Panel.fit(
            "Welcome to SecAuditAI",
            title="SecAuditAI",
            border_style="blue"
        ))
        self.show_main_menu() 