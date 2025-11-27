"""
Report generation module for SecAuditAI.
"""
import os
import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
import jinja2
from rich.console import Console
from rich.table import Table
try:
    import pdfkit
except ImportError:  # pragma: no cover - optional dependency
    pdfkit = None

console = Console()

class ReportGenerator:
    """Generates reports in various formats."""
    
    def __init__(self, output_dir: str = "~/.secauditai/results"):
        self.output_dir = os.path.expanduser(output_dir)
        self._ensure_output_dir()
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=True
        )

    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists."""
        os.makedirs(self.output_dir, exist_ok=True)

    def _get_report_path(self, scan_type: str, format: str) -> str:
        """Generate report file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_type}_{timestamp}.{format}"
        return os.path.join(self.output_dir, filename)

    def generate_json_report(self, results: Dict[str, Any], scan_type: str) -> str:
        """Generate JSON report."""
        report_path = self._get_report_path(scan_type, "json")
        
        report_data = {
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        return report_path

    def generate_html_report(self, results: Dict[str, Any], scan_type: str) -> str:
        """Generate HTML report."""
        report_path = self._get_report_path(scan_type, "html")
        
        template = self.env.get_template("report.html")
        report_data = {
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
        
        html_content = template.render(**report_data)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
            
        return report_path

    def generate_pdf_report(self, results: Dict[str, Any], scan_type: str) -> str:
        """Generate PDF report."""
        html_path = self.generate_html_report(results, scan_type)
        pdf_path = self._get_report_path(scan_type, "pdf")
        
        if pdfkit is None:
            console.print("[yellow]pdfkit is not installed. Returning HTML report instead.[/yellow]")
            return html_path
        
        try:
            pdfkit.from_file(html_path, pdf_path)
            return pdf_path
        except Exception as e:
            console.print(f"[red]Error generating PDF report: {str(e)}[/red]")
            return html_path

    def generate_report(self, results: Dict[str, Any], scan_type: str, format: str = "json") -> str:
        """Generate report in specified format."""
        if format == "json":
            return self.generate_json_report(results, scan_type)
        elif format == "html":
            return self.generate_html_report(results, scan_type)
        elif format == "pdf":
            return self.generate_pdf_report(results, scan_type)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def list_reports(self) -> List[Dict[str, str]]:
        """List all available reports."""
        reports = []
        for file in os.listdir(self.output_dir):
            if file.endswith(('.json', '.html', '.pdf')):
                file_path = os.path.join(self.output_dir, file)
                reports.append({
                    "name": file,
                    "path": file_path,
                    "type": file.split('.')[-1],
                    "size": os.path.getsize(file_path),
                    "created": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                })
        return reports

    def display_reports(self) -> None:
        """Display available reports in a table."""
        reports = self.list_reports()
        
        if not reports:
            console.print("[yellow]No reports available[/yellow]")
            return
            
        table = Table(title="Available Reports")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Size", style="blue")
        table.add_column("Created", style="white")
        
        for report in reports:
            table.add_row(
                report["name"],
                report["type"],
                f"{report['size'] / 1024:.1f} KB",
                report["created"]
            )
            
        console.print(table) 


def generate_zero_day_report(
    code_results: Dict[str, Any],
    network_results: Dict[str, Any],
    format: str = "html"
) -> str:
    """Produce a lightweight zero-day report used in the test-suite."""
    if format != "html":
        raise ValueError("Only HTML formatted zero-day reports are supported.")

    code_section = json.dumps(code_results, indent=2)
    network_section = json.dumps(network_results, indent=2)
    return (
        "<html><body>"
        "<h1>Zero-Day Detection Report</h1>"
        f"<h2>Code Analysis</h2><pre>{code_section}</pre>"
        f"<h2>Network Analysis</h2><pre>{network_section}</pre>"
        "</body></html>"
    )