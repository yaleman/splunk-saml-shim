""" cli for the web interface for the project that outgrew its intention """

import logging
from typing import Optional

import click
import uvicorn  # type: ignore


@click.command()
@click.option("--reload", is_flag=True)
@click.option("--port", type=int, default=8000)
@click.option("--host", type=str)
@click.option("--proxy-headers", is_flag=True)
def cli(
    reload: bool = False,
    port: int = 8000,
    host: Optional[str] = None,
    proxy_headers: bool = False,
) -> None:
    """github_linter server"""

    if host is None:
        host = "0.0.0.0"  # nosec

    logging.basicConfig(level=logging.DEBUG)

    uvicorn.run(
        app="splunk_saml_shim:app",
        host=host,
        port=port,
        proxy_headers=proxy_headers,
        workers=4,
        reload=reload,
        reload_dirs=["splunk_saml_shim/"],
    )

if __name__ == "__main__":
    cli()
