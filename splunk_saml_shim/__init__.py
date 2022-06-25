""" A shim that sits between splunk and you, to make pulling the SAML metadata easier """

#pylint: disable=too-few-public-methods

from typing import Any, Dict

import aiohttp
from fastapi import Depends, FastAPI, Response, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseSettings


URI_SP_METADATA = "/services/admin/SAML-sp-metadata"

class AppConfig(BaseSettings):
    """ configuration """
    splunk_hostname: str
    splunk_port: int = 8089
    splunk_scheme: str = "https"

    class Config:
        """ config of the config """
        env_file = '.env'
        env_file_encoding = 'utf-8'

    @property
    def base_url(self):
        """ returns the URL """
        return f"{self.splunk_scheme}://{self.splunk_hostname}:{self.splunk_port}"

settings = AppConfig()
app = FastAPI()

security = HTTPBasic()


@app.get("/health")
async def health():
    """ health check """
    return "OK"

@app.get("/")
async def root(request: Request, credentials= Depends(security)) -> Dict[str, Any]:
    """ homepage """
    async with aiohttp.ClientSession() as session:
        response = await session.get(f"{settings.base_url}/")
        content = await response.content.read()

    # want content from spMetadataPayload
    return {
        "message" : settings.base_url,
        "content" : content,
        "headers" : request.headers,
        "creds" : credentials
        }
