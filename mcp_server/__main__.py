import os
import sys
from datetime import datetime, timezone

from mcp_server import __version__
from mcp_server.server import StdioMcpServer


def main() -> None:
    print(
        (
            "[ioc-project-mcp] startup "
            f"ts={datetime.now(timezone.utc).isoformat()} "
            f"executable={sys.executable} "
            f"cwd={os.getcwd()} "
            f"argv={sys.argv!r}"
        ),
        file=sys.stderr,
        flush=True,
    )
    server = StdioMcpServer()
    server.serve_forever()
    print("[ioc-project-mcp] stopped", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
