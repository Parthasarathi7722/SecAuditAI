"""
Main CLI module for SecAuditAI.
"""
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Dict, Any, Optional
from .plugins import PluginManager
from .config import ConfigManager
from .ai import AIManager
from .reports import ReportGenerator
from .tui import TUI

console = Console()

@click.group()
@click.version_option()
def main():
    """SecAuditAI - AI-powered security audit tool."""
    pass

@main.command()
def interactive():
    """Launch interactive TUI mode."""
    tui = TUI()
    tui.run()

@main.group()
def scan():
    """Perform security scans."""
    pass

@scan.command()
@click.option('--profile', help='AWS profile to use')
@click.option('--region', help='AWS region to scan')
@click.option('--output-format', type=click.Choice(['json', 'html', 'pdf']), default='json')
def aws(profile, region, output_format):
    """Scan AWS infrastructure."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning AWS infrastructure...", total=None)
        
        try:
            plugin_manager = PluginManager()
            plugin = plugin_manager.get_plugin('aws')
            if plugin:
                config = ConfigManager().get_config().cloud.dict()
                results = plugin.scan(
                    target='aws',
                    profile=profile or config.get('aws_profile'),
                    region=region or config.get('aws_region')
                )
                
                # Generate report
                report_generator = ReportGenerator()
                report_path = report_generator.generate_report(results, 'aws', output_format)
                
                console.print(Panel.fit(
                    Text(f"Scan completed. Report saved to: {report_path}", style="green"),
                    title="SecAuditAI",
                    border_style="blue"
                ))
            else:
                console.print("[red]AWS scanner plugin not found[/red]")
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}[/red]")

@scan.command()
@click.option('--subscription', help='Azure subscription ID')
@click.option('--resource-group', help='Azure resource group')
@click.option('--output-format', type=click.Choice(['json', 'html', 'pdf']), default='json')
def azure(subscription, resource_group, output_format):
    """Scan Azure infrastructure."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning Azure infrastructure...", total=None)
        
        try:
            plugin_manager = PluginManager()
            plugin = plugin_manager.get_plugin('azure')
            if plugin:
                config = ConfigManager().get_config().cloud.dict()
                results = plugin.scan(
                    target='azure',
                    subscription=subscription or config.get('azure_subscription'),
                    resource_group=resource_group or config.get('azure_resource_group')
                )
                
                # Generate report
                report_generator = ReportGenerator()
                report_path = report_generator.generate_report(results, 'azure', output_format)
                
                console.print(Panel.fit(
                    Text(f"Scan completed. Report saved to: {report_path}", style="green"),
                    title="SecAuditAI",
                    border_style="blue"
                ))
            else:
                console.print("[red]Azure scanner plugin not found[/red]")
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}[/red]")

@scan.command()
@click.option('--path', help='Path to code directory or file')
@click.option('--language', help='Programming language')
@click.option('--output-format', type=click.Choice(['json', 'html', 'pdf']), default='json')
def code(path, language, output_format):
    """Scan source code for security issues."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning code...", total=None)
        
        try:
            plugin_manager = PluginManager()
            plugin = plugin_manager.get_plugin('code')
            if plugin:
                results = plugin.scan(
                    target='code',
                    path=path,
                    language=language
                )
                
                # Generate report
                report_generator = ReportGenerator()
                report_path = report_generator.generate_report(results, 'code', output_format)
                
                console.print(Panel.fit(
                    Text(f"Scan completed. Report saved to: {report_path}", style="green"),
                    title="SecAuditAI",
                    border_style="blue"
                ))
            else:
                console.print("[red]Code scanner plugin not found[/red]")
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}[/red]")

@scan.command()
@click.option('--path', help='Path to project directory')
@click.option('--output-format', type=click.Choice(['json', 'html', 'pdf']), default='json')
def sbom(path, output_format):
    """Generate and analyze SBOM."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating and analyzing SBOM...", total=None)
        
        try:
            plugin_manager = PluginManager()
            plugin = plugin_manager.get_plugin('sbom')
            if plugin:
                results = plugin.scan(
                    target='sbom',
                    path=path
                )
                
                # Generate report
                report_generator = ReportGenerator()
                report_path = report_generator.generate_report(results, 'sbom', output_format)
                
                console.print(Panel.fit(
                    Text(f"Scan completed. Report saved to: {report_path}", style="green"),
                    title="SecAuditAI",
                    border_style="blue"
                ))
            else:
                console.print("[red]SBOM scanner plugin not found[/red]")
        except Exception as e:
            console.print(f"[red]Error during scan: {str(e)}[/red]")

@main.group()
def ai():
    """AI-related commands."""
    pass

@ai.command()
@click.option('--type', help='Type of dataset to download')
def dataset(type):
    """Download security datasets for AI training."""
    console.print(Panel.fit(
        Text("Dataset Download Module", style="bold blue"),
        title="SecAuditAI",
        border_style="blue"
    ))
    # TODO: Implement dataset download logic

@ai.command()
@click.option('--model', help='Model to train')
@click.option('--dataset', help='Path to training dataset')
@click.option('--epochs', type=int, help='Number of training epochs')
def train(model, dataset, epochs):
    """Train AI models on security datasets."""
    console.print(Panel.fit(
        Text("Model Training Module", style="bold blue"),
        title="SecAuditAI",
        border_style="blue"
    ))
    # TODO: Implement model training logic

@main.command()
def init():
    """Initialize SecAuditAI configuration."""
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    console.print(Panel.fit(
        Text("Initializing SecAuditAI configuration...", style="bold blue"),
        title="SecAuditAI",
        border_style="blue"
    ))
    
    # Save default configuration
    config_manager.save_config()
    
    console.print("[green]Configuration initialized successfully![/green]")

if __name__ == '__main__':
    main() 