"""
Hide CLI Interface.
Modern, sleek desktop terminal interface for zero-knowledge encrypted vaults.
Supports packaging, mounting workspaces, differential sync, status, and emergency lockdown.
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn
from rich.table import Table

from hide.core.kdf import (
    PasswordMismatchError,
    InvalidPasswordError,
    prompt_password_with_confirmation,
)
from hide.core.metadata import read_vault_metadata, META_FILENAME, unlock_vault_metadata
from hide.core.models import TransactionState
from hide.core.recovery import get_vault_operational_status, recover_interrupted_vault
from hide.core.registry import VaultRegistry, get_default_vaults_dir
from hide.core.vault import (
    init_vault,
    pack_directory,
    verify_vault_integrity,
    VaultOperationError,
    VaultVerificationError,
)
from hide.core.workspace import (
    open_vault_workspace,
    close_vault_workspace,
    panic_lock_all_workspaces,
    SNAPSHOT_FILENAME,
    WorkspaceSnapshot,
    get_default_workspaces_dir,
)

console = Console()


def prompt_password(confirm: bool = False, prompt_text: str = "Password: ") -> str:
    """Prompts for password securely without terminal echo."""
    if confirm:
        return prompt_password_with_confirmation(
            prompt=f"{prompt_text}",
            confirm_prompt="Confirm password: ",
        )
    pwd = getpass.getpass(prompt_text)
    if not pwd:
        console.print("[red]Password cannot be empty.[/red]")
        sys.exit(1)
    return pwd


def format_bytes(num_bytes: int) -> str:
    """Formats bytes into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context):
    """Hide — Zero-Knowledge Local Encrypted Vault CLI."""
    if ctx.invoked_subcommand is None:
        console.print(
            Panel.fit(
                "[bold cyan]HIDE[/bold cyan] — Encrypted Local Vault CLI\n"
                "[dim]Zero-Knowledge Authenticated Local Folder Encryption[/dim]\n\n"
                "Run [bold green]hide --help[/bold green] to see available commands.\n"
                "To encrypt current folder: [bold yellow]hide .[/bold yellow]\n"
                "To list vaults:           [bold yellow]hide list[/bold yellow]\n"
                "To open a vault:          [bold yellow]hide open <id|name>[/bold yellow]\n"
                "To close / lock a vault:   [bold yellow]hide close[/bold yellow]\n"
                "Emergency lock all:       [bold red]hide panic[/bold red]",
                title="🔒 HIDE",
                border_style="cyan",
            )
        )


@cli.command("init")
@click.argument("path", required=False, type=click.Path())
@click.option("--name", "-n", help="Friendly name for the vault container.")
def init_cmd(path: Optional[str], name: Optional[str]):
    """Initialize a new empty vault container."""
    if path:
        target_path = Path(path).resolve()
    else:
        vault_name = name or "DefaultVault"
        target_path = get_default_vaults_dir() / f"{vault_name}.hide"

    v_name = name or target_path.stem.replace(".hide", "")

    console.print(f"[bold cyan]Initializing vault:[/bold cyan] {v_name}")
    console.print(f"[dim]Location: {target_path}[/dim]\n")

    try:
        pwd = prompt_password(confirm=True, prompt_text="Create vault password: ")
        with console.status("[bold green]Deriving master key and generating vault container..."):
            meta, master_key = init_vault(target_path, v_name, pwd)
            master_key.zeroize()

        console.print(f"\n[bold green]✔ Vault successfully initialized![/bold green]")
        console.print(f"Vault ID: [dim]{meta.vault_id}[/dim]")
        console.print(f"Cipher:   [dim]{meta.cipher} (Argon2id KDF)[/dim]")
    except PasswordMismatchError:
        console.print("[bold red]Error:[/bold red] Passwords do not match.")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Initialization failed:[/bold red] {exc}")
        sys.exit(1)


@cli.command(".")
@click.option("--name", "-n", help="Name for the resulting vault.")
@click.option("--dest", "-d", help="Destination path for vault container.")
@click.option("--keep", is_flag=True, help="Keep original unencrypted files (do not shred).")
def pack_current_dir(name: Optional[str], dest: Optional[str], keep: bool):
    """Encrypt current working directory in-place into an encrypted vault."""
    source_dir = Path.cwd().resolve()
    v_name = name or source_dir.name

    if dest:
        target_vault = Path(dest).resolve()
    else:
        target_vault = get_default_vaults_dir() / f"{v_name}.hide"

    console.print(Panel.fit(
        f"[bold yellow]Encrypting Current Directory[/bold yellow]\n"
        f"Source: [cyan]{source_dir}[/cyan]\n"
        f"Target: [cyan]{target_vault}[/cyan]\n"
        f"Shred Originals: [red]{'No' if keep else 'Yes (Verified)'}[/red]",
        title="🔒 HIDE PACK",
        border_style="yellow",
    ))

    try:
        pwd = prompt_password(confirm=True, prompt_text="Set vault password: ")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Encrypting files...", total=None)

            def update_progress(rel_path: str, processed: int, total: int):
                progress.update(task, completed=processed, total=total, description=f"[cyan]{rel_path[:30]}")

            meta = pack_directory(
                source_dir=source_dir,
                target_vault_dir=target_vault,
                vault_name=v_name,
                password=pwd,
                delete_original=not keep,
                progress_callback=update_progress,
            )

        console.print(f"\n[bold green]✔ Directory encrypted successfully![/bold green]")
        console.print(f"Vault: [bold]{meta.vault_name}[/bold] ({target_vault})")
        if not keep:
            console.print("[dim]Original plaintext files have been safely verified and removed.[/dim]")
    except PasswordMismatchError:
        console.print("[bold red]Error:[/bold red] Passwords do not match.")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[bold red]Encryption failed:[/bold red] {exc}")
        sys.exit(1)


@cli.command("pack")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--name", "-n", help="Name for the resulting vault.")
@click.option("--dest", "-d", help="Destination path for vault container.")
@click.option("--keep", is_flag=True, help="Keep original unencrypted files.")
def pack_explicit_dir(directory: str, name: Optional[str], dest: Optional[str], keep: bool):
    """Encrypt a specified directory into a vault container."""
    source_dir = Path(directory).resolve()
    v_name = name or source_dir.name
    target_vault = Path(dest).resolve() if dest else get_default_vaults_dir() / f"{v_name}.hide"

    console.print(f"[bold cyan]Packing directory:[/bold cyan] {source_dir} -> {target_vault}")

    try:
        pwd = prompt_password(confirm=True, prompt_text="Set vault password: ")
        with console.status("[bold green]Encrypting and verifying directory..."):
            meta = pack_directory(
                source_dir=source_dir,
                target_vault_dir=target_vault,
                vault_name=v_name,
                password=pwd,
                delete_original=not keep,
            )
        console.print(f"\n[bold green]✔ Folder '{source_dir.name}' packed into vault '{meta.vault_name}'![/bold green]")
    except Exception as exc:
        console.print(f"[bold red]Packing failed:[/bold red] {exc}")
        sys.exit(1)


@cli.command("list")
def list_cmd():
    """List all registered vaults and their operational status."""
    reg = VaultRegistry()
    vaults = reg.list_vaults()

    if not vaults:
        console.print("[dim]No vaults registered yet. Run [bold green]hide init[/bold green] or [bold yellow]hide .[/bold yellow] to create one.[/dim]")
        return

    table = Table(title="🔒 Registered Encrypted Vaults", border_style="cyan")
    table.add_column("#", justify="center", style="bold yellow")
    table.add_column("Vault Name", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right")
    table.add_column("Path", style="dim")

    for i, v in enumerate(vaults, start=1):
        if v.status == TransactionState.CLOSED:
            status_render = "[green]LOCKED[/green]"
        elif v.status == TransactionState.OPEN:
            status_render = "[bold yellow]OPEN[/bold yellow]"
        elif v.status == TransactionState.PANIC_LOCKED:
            status_render = "[bold red]PANIC LOCKED[/bold red]"
        elif v.status == TransactionState.RECOVERY_REQUIRED:
            status_render = "[bold red]RECOVERY[/bold red]"
        else:
            status_render = f"[cyan]{v.status.value}[/cyan]"

        table.add_row(
            str(i),
            v.name,
            status_render,
            format_bytes(v.size_on_disk_bytes),
            v.path,
        )

    console.print(table)


@cli.command("open")
@click.argument("vault_identifier")
@click.option("--dest", "-d", help="Custom destination directory for workspace.")
def open_cmd(vault_identifier: str, dest: Optional[str]):
    """
    Authenticate and decrypt a vault into a temporary workspace.
    """
    reg = VaultRegistry()
    summary = reg.find_vault(vault_identifier)
    if not summary:
        # Check if direct directory was passed
        p = Path(vault_identifier).resolve()
        if p.is_dir() and (p / META_FILENAME).is_file():
            vault_path = p
        else:
            console.print(f"[bold red]Error:[/bold red] Vault '{vault_identifier}' not found in registry.")
            sys.exit(1)
    else:
        vault_path = Path(summary.path)

    console.print(f"[bold cyan]Opening Vault:[/bold cyan] {vault_path.name}")
    pwd = prompt_password(confirm=False, prompt_text="Enter vault password: ")

    target_ws = Path(dest).resolve() if dest else None

    try:
        with console.status("[bold green]Authenticating and unpacking workspace..."):
            workspace_path, manifest = open_vault_workspace(
                vault_dir=vault_path,
                password=pwd,
                target_workspace=target_ws,
            )

        console.print(Panel.fit(
            f"[bold green]✔ Vault Unlocked & Mounted![/bold green]\n"
            f"Workspace: [bold white]{workspace_path}[/bold white]\n"
            f"Files:     [cyan]{manifest.get_file_count()}[/cyan] ({format_bytes(manifest.get_total_size())})\n\n"
            f"[dim]Work in this folder normally. When finished, run:[/dim]\n"
            f"[bold yellow]hide close[/bold yellow] [dim]or[/dim] [bold yellow]hide close \"{workspace_path}\"[/bold yellow]",
            title="🔓 VAULT OPEN",
            border_style="green",
        ))
    except InvalidPasswordError:
        console.print("[bold red]Access Denied:[/bold red] Incorrect password.")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Failed to open vault:[/bold red] {exc}")
        sys.exit(1)


@cli.command("close")
@click.argument("target", required=False)
def close_cmd(target: Optional[str]):
    """
    Re-encrypt changes from workspace, update vault, and shred workspace.
    If no target is given, looks in current directory or active workspaces.
    """
    workspace_path: Optional[Path] = None

    if target:
        cand = Path(target).resolve()
        if (cand / SNAPSHOT_FILENAME).is_file():
            workspace_path = cand
        else:
            # Check if vault name/id was passed
            reg = VaultRegistry()
            summary = reg.find_vault(target)
            if summary:
                # Find matching workspace
                ws_dir = get_default_workspaces_dir()
                for item in ws_dir.iterdir():
                    if item.is_dir() and (item / SNAPSHOT_FILENAME).is_file():
                        snap = WorkspaceSnapshot.load_from_file(item / SNAPSHOT_FILENAME)
                        if snap.vault_id == summary.vault_id:
                            workspace_path = item
                            break
    else:
        # Check current directory
        cwd = Path.cwd().resolve()
        if (cwd / SNAPSHOT_FILENAME).is_file():
            workspace_path = cwd
        else:
            # Check default workspaces dir for any active workspace
            ws_dir = get_default_workspaces_dir()
            active_workspaces = [
                d for d in ws_dir.iterdir() if d.is_dir() and (d / SNAPSHOT_FILENAME).is_file()
            ]
            if len(active_workspaces) == 1:
                workspace_path = active_workspaces[0]
            elif len(active_workspaces) > 1:
                console.print("[yellow]Multiple workspaces are currently active. Please specify which to close:[/yellow]")
                for w in active_workspaces:
                    console.print(f" - [bold white]{w}[/bold white]")
                sys.exit(1)

    if not workspace_path or not (workspace_path / SNAPSHOT_FILENAME).is_file():
        console.print("[bold red]Error:[/bold red] No active vault workspace found to close.")
        console.print("[dim]Specify the workspace path or run inside the opened workspace directory.[/dim]")
        sys.exit(1)

    console.print(f"[bold cyan]Closing workspace:[/bold cyan] {workspace_path}")
    pwd = prompt_password(confirm=False, prompt_text="Enter vault password: ")

    try:
        with console.status("[bold green]Detecting differential changes, re-encrypting, and wiping workspace..."):
            close_vault_workspace(workspace_path, pwd)

        console.print("\n[bold green]✔ Changes re-encrypted and committed into vault![/bold green]")
        console.print("[dim]Workspace securely wiped. Vault is now LOCKED.[/dim]")
    except InvalidPasswordError:
        console.print("[bold red]Access Denied:[/bold red] Incorrect password.")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Failed to close workspace:[/bold red] {exc}")
        sys.exit(1)


@cli.command("status")
@click.argument("vault_identifier", required=False)
def status_cmd(vault_identifier: Optional[str]):
    """Display real-time vault operational status, integrity, and active leases."""
    reg = VaultRegistry()
    if vault_identifier:
        summary = reg.find_vault(vault_identifier)
        if summary:
            vault_path = Path(summary.path)
        else:
            cand = Path(vault_identifier).resolve()
            if cand.is_dir() and (cand / META_FILENAME).is_file():
                vault_path = cand
            else:
                console.print(f"[bold red]Error:[/bold red] Vault '{vault_identifier}' not found.")
                sys.exit(1)
    else:
        vaults = reg.list_vaults()
        if not vaults:
            console.print("[dim]No registered vaults found.[/dim]")
            return
        summary = vaults[0]
        vault_path = Path(summary.path)

    meta_file = vault_path / META_FILENAME
    if not meta_file.is_file():
        console.print(f"[bold red]Error:[/bold red] Corrupted vault container: missing {META_FILENAME}")
        sys.exit(1)

    meta = read_vault_metadata(meta_file)
    op_status, lock_state = get_vault_operational_status(vault_path)

    status_color = "green" if op_status == TransactionState.CLOSED else ("yellow" if op_status == TransactionState.OPEN else "red")

    panel_content = (
        f"Vault Name:     [bold white]{meta.vault_name}[/bold white]\n"
        f"Vault ID:       [dim]{meta.vault_id}[/dim]\n"
        f"Status:         [{status_color}]{op_status.value}[/{status_color}]\n"
        f"Disk Location:  [dim]{vault_path}[/dim]\n"
        f"Cipher Suite:   [cyan]{meta.cipher.upper()} (Argon2id KDF)[/cyan]\n"
    )
    if lock_state and lock_state.workspace_path:
        panel_content += f"Active Staging: [bold yellow]{lock_state.workspace_path}[/bold yellow] (PID: {lock_state.pid})\n"

    console.print(Panel(panel_content, title=f"🔒 Vault Status — {meta.vault_name}", border_style="cyan"))


@cli.command("panic")
def panic_cmd():
    """EMERGENCY: Instantly unmount and securely shred all active workspaces."""
    console.print("[bold red]🚨 EMERGENCY LOCKDOWN TRIGGERED 🚨[/bold red]")
    with console.status("[bold red]Shredding all decrypted staging workspaces..."):
        shredded = panic_lock_all_workspaces()

    if shredded:
        console.print(f"[bold green]✔ Successfully shredded {len(shredded)} active workspace(s):[/bold green]")
        for item in shredded:
            console.print(f" - [dim]{item}[/dim]")
    else:
        console.print("[dim]No active workspaces were detected.[/dim]")

    console.print("[bold green]Workstation secure. All vaults are locked.[/bold green]")


@cli.command("lock")
@click.argument("vault_identifier", required=False)
@click.option("--all", "lock_all", is_flag=True, help="Lock all active vaults immediately.")
@click.pass_context
def lock_cmd(ctx: click.Context, vault_identifier: Optional[str], lock_all: bool):
    """Lock an open vault, or lock all active vaults with --all."""
    if lock_all or vault_identifier == "--all":
        ctx.invoke(panic_cmd)
    elif vault_identifier:
        ctx.invoke(close_cmd, target=vault_identifier)
    else:
        ctx.invoke(close_cmd)


@cli.command("verify")
@click.argument("vault_identifier")
def verify_cmd(vault_identifier: str):
    """Cryptographically verify all encrypted objects in a vault against the manifest."""
    reg = VaultRegistry()
    summary = reg.find_vault(vault_identifier)
    if not summary:
        console.print(f"[bold red]Error:[/bold red] Could not find vault '{vault_identifier}'.")
        sys.exit(1)

    vault_path = Path(summary.path)
    meta_path = vault_path / META_FILENAME
    if not meta_path.is_file():
        console.print(f"[bold red]Error:[/bold red] Missing {META_FILENAME} in {vault_path}")
        sys.exit(1)

    meta = read_vault_metadata(meta_path)
    console.print(f"[bold cyan]Auditing Vault:[/bold cyan] {meta.vault_name} ([dim]{vault_path}[/dim])")
    pwd = prompt_password(confirm=False, prompt_text="Enter vault password: ")

    try:
        with console.status("[bold green]Verifying GCM authentication tags across all objects..."):
            with unlock_vault_metadata(meta, pwd) as key:
                verify_vault_integrity(vault_path, meta.vault_id, key)

        console.print("\n[bold green]✔ Cryptographic Audit Passed![/bold green] All objects are 100% authentic with zero corruption.")
    except InvalidPasswordError:
        console.print("[bold red]Access Denied:[/bold red] Incorrect password.")
        sys.exit(1)
    except VaultVerificationError as exc:
        console.print(f"[bold red]AUDIT FAILURE:[/bold red] {exc}")
        sys.exit(1)


@cli.command("repair")
@click.argument("vault_identifier")
def repair_cmd(vault_identifier: str):
    """Inspect and safely recover an interrupted or crashed vault transaction."""
    reg = VaultRegistry()
    summary = reg.find_vault(vault_identifier)
    if not summary:
        console.print(f"[bold red]Error:[/bold red] Could not find vault '{vault_identifier}'.")
        sys.exit(1)

    vault_path = Path(summary.path)
    result_msg = recover_interrupted_vault(vault_path)
    console.print(f"[bold green]{result_msg}[/bold green]")


def main():
    cli()


if __name__ == "__main__":
    main()
