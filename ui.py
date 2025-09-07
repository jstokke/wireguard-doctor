from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.status import Status
from rich.panel import Panel
from rich.text import Text

# Initialize the console
console = Console()

def print_welcome():
    """Prints a welcome banner for the application."""
    console.print(Panel(
        Text("WG-Doctor: Your WireGuard Troubleshooting Assistant", justify="center", style="bold magenta"),
        title="[bold cyan]Welcome[/bold cyan]",
        border_style="green"
    ))
    console.print()

def start_task(message: str) -> Status:
    """
    Displays a spinner for a background task.

    Args:
        message: The message to display next to the spinner.

    Returns:
        The Status object, which can be stopped later.
    """
    status = console.status(f"[bold green]{message}[/bold green]")
    status.start()
    return status

def end_task(status: Status, success: bool, message: str = ""):
    """
    Stops a task spinner and prints a success or failure message.

    Args:
        status: The Status object to stop.
        success: Boolean indicating if the task was successful.
        message: An optional message to print after the status line.
    """
    status.stop()
    if success:
        console.print(f"[bold green]✔[/bold green] {message or 'Done'}")
    else:
        console.print(f"[bold red]✖[/bold red] {message or 'Failed'}")

def print_info(message: str):
    """Prints an informational message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")

def print_error(message: str):
    """Prints an error message."""
    console.print(f"[bold red]Error:[/bold red] {message}")

def ask_question(prompt: str, choices: list[str] | None = None, default: str | None = None) -> str:
    """

    Asks the user a question and returns their answer.

    Args:
        prompt: The question to ask.
        choices: A list of valid choices.
        default: The default value if the user enters nothing.

    Returns:
        The user's answer as a string.
    """
    return Prompt.ask(f"[bold yellow]?[/bold yellow] {prompt}", choices=choices, default=default)

def ask_confirm(prompt: str, default: bool = False) -> bool:
    """
    Asks the user a yes/no question.

    Args:
        prompt: The question to ask.
        default: The default boolean value.

    Returns:
        True for yes, False for no.
    """
    return Confirm.ask(f"[bold yellow]?[/bold yellow] {prompt}", default=default)
