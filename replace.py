import re
import sys

def process(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add output import
    if "from cli_core_yo import output" not in content:
        content = content.replace("import typer\n", "import typer\nfrom cli_core_yo import output\n")

    # Replace specific console.prints
    content = re.sub(r'console\.print\([^"]*?\[red\]✗\[/red\]  Error: \{e\}"\)', 'output.error(f"Error: {e}")', content)
    content = re.sub(r'console\.print\([^"]*?\[red\]✗\[/red\]  ([^"]+)"\)', r'output.error("\1")', content)
    content = re.sub(r'console\.print\([^"]*?\[green\]✓\[/green\]  ([^"]+)"\)', r'output.success("\1")', content)
    content = re.sub(r'console\.print\([^"]*?\[yellow\]⚠(?:\s|\[/yellow\])\s*([^"]+)"\)', r'output.warning("\1")', content)
    
    # Replace remaining console.print with output.info
    content = re.sub(r'console\.print\(', 'output.info(', content)
    content = re.sub(r'console\.print_json\(', 'print(', content)  # Fallback for json

    # Also replace raise typer.Exit(1) right after output.error with output.abort
    # Actually, simpler to just find output.error and raise typer.Exit(1)
    content = re.sub(r'output\.error\(([^)]+)\)\n\s*raise typer\.Exit\(1\)', r'output.abort(\1)', content)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

process("daylily_cognito/plugins/core.py")
print("Done")
