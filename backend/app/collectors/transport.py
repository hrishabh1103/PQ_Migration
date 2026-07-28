import os
import glob
import fnmatch
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)

class LinuxTransport(ABC):
    """
    Abstract transport interface decoupling collection logic from SSH/local execution.
    Exposes read-only metadata inspection and bounded file discovery.
    """

    @abstractmethod
    async def run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        """Runs a command and returns (return_code, stdout, stderr)."""
        pass

    @abstractmethod
    async def read_file(self, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
        """Reads up to max_bytes from a file. Returns None if unreadable or missing."""
        pass

    @abstractmethod
    async def file_exists(self, path: str) -> bool:
        """Returns True if the file exists and is accessible."""
        pass

    @abstractmethod
    async def list_files(
        self,
        root: str,
        patterns: List[str],
        max_depth: int = 3,
        max_results: int = 100,
        max_file_size: int = 10_000_000
    ) -> List[Dict[str, Any]]:
        """
        Bounded file discovery API enforcing explicit root, depth limits, result caps, and size limits.
        Never recursively scans arbitrary filesystem trees.
        """
        pass


class LocalTransport(LinuxTransport):
    """
    Local Linux execution transport using bounded subprocesses and file inspections.
    """

    async def run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                proc.returncode or 0,
                stdout_data.decode("utf-8", errors="replace"),
                stderr_data.decode("utf-8", errors="replace")
            )
        except asyncio.TimeoutError:
            logger.warning(f"LocalTransport command execution timed out ({timeout}s): {cmd}")
            return (-1, "", f"Execution timed out after {timeout}s")
        except Exception as e:
            logger.warning(f"LocalTransport command execution failed: {cmd} - {e}")
            return (-1, "", str(e))

    async def read_file(self, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        except Exception as e:
            logger.debug(f"Failed to read file '{path}': {e}")
            return None

    async def file_exists(self, path: str) -> bool:
        return os.path.exists(path)

    async def list_files(
        self,
        root: str,
        patterns: List[str],
        max_depth: int = 3,
        max_results: int = 100,
        max_file_size: int = 10_000_000
    ) -> List[Dict[str, Any]]:
        results = []
        if not os.path.exists(root):
            return results

        root_depth = root.rstrip(os.sep).count(os.sep)

        for current_root, dirs, files in os.walk(root):
            curr_depth = current_root.count(os.sep) - root_depth
            if curr_depth > max_depth:
                dirs.clear()
                continue

            for fname in files:
                if len(results) >= max_results:
                    break

                matched = any(fnmatch.fnmatch(fname, pat) for pat in patterns)
                if not matched:
                    continue

                full_path = os.path.join(current_root, fname)
                try:
                    stat = os.stat(full_path)
                    if stat.st_size <= max_file_size:
                        results.append({
                            "path": full_path,
                            "filename": fname,
                            "size_bytes": stat.st_size,
                            "modified_at": stat.st_mtime
                        })
                except Exception:
                    continue

            if len(results) >= max_results:
                break

        return results


class SSHTransport(LinuxTransport):
    """
    SSH Remote transport foundation (FOUNDATION READY).
    Designed for remote collection without persisting SSH credentials.
    """

    def __init__(self, hostname: str, port: int = 22):
        self.hostname = hostname
        self.port = port

    async def run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        raise NotImplementedError("SSH remote collection is FOUNDATION READY (Credential storage not implemented in V1).")

    async def read_file(self, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
        raise NotImplementedError("SSH remote collection is FOUNDATION READY.")

    async def file_exists(self, path: str) -> bool:
        raise NotImplementedError("SSH remote collection is FOUNDATION READY.")

    async def list_files(
        self,
        root: str,
        patterns: List[str],
        max_depth: int = 3,
        max_results: int = 100,
        max_file_size: int = 10_000_000
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError("SSH remote collection is FOUNDATION READY.")


class AgentTransport(LinuxTransport):
    """
    Installed Agent transport foundation (PLANNED).
    """

    async def run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        raise NotImplementedError("Agent transport is PLANNED.")

    async def read_file(self, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
        raise NotImplementedError("Agent transport is PLANNED.")

    async def file_exists(self, path: str) -> bool:
        raise NotImplementedError("Agent transport is PLANNED.")

    async def list_files(
        self,
        root: str,
        patterns: List[str],
        max_depth: int = 3,
        max_results: int = 100,
        max_file_size: int = 10_000_000
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError("Agent transport is PLANNED.")
