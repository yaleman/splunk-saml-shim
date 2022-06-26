""" A shim that sits between splunk and you, to make pulling the SAML metadata easier """

# pylint: disable=too-few-public-methods

import logging
import json
from typing import Optional
import urllib.parse

import aiohttp
import aiohttp.client_exceptions
from bs4 import BeautifulSoup
import bs4.element # type: ignore
from fastapi import Depends, FastAPI, Response, HTTPException

from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseSettings


URI_SP_METADATA = "/services/admin/SAML-sp-metadata"


class AppConfig(BaseSettings):
    """configuration"""

    splunk_hostname: str
    splunk_port: int = 8089
    splunk_scheme: str = "https"
    splunk_username: Optional[str] = None
    splunk_password: Optional[str] = None

    rewrite_location: bool = False
    rewrite_host: Optional[str] = None
    rewrite_scheme: Optional[str] = None

    log_level: str = "INFO"

    class Config:
        """config of the config"""

        env_file = ".env"
        env_file_encoding = "utf-8"

    @property
    def base_url(self) -> str:
        """returns the URL"""
        return f"{self.splunk_scheme}://{self.splunk_hostname}:{self.splunk_port}"


settings = AppConfig()
logging.basicConfig(level=settings.log_level)
app = FastAPI()

# this grabs the basic auth
security = HTTPBasic(auto_error=False)


@app.get("/health")
async def health() -> str:
    """health check"""
    return "OK"

def get_metadata(soup: BeautifulSoup) -> bs4.element.Tag:
    """ grabs the SAML metadata """
    return soup.find("s:key", attrs={"name": "spMetadata"})

def update_netloc(parsed_url: urllib.parse.ParseResult) -> str:
    """ take the parsed URL and return an updated location """
    scheme = settings.dict().get("rewrite_scheme", parsed_url.scheme)
    netloc = settings.dict().get("rewrite_host", parsed_url.netloc)

    retval = f"{scheme}://{netloc}{parsed_url.path}"
    if parsed_url.params:
        retval += f";{parsed_url.params}"
    if parsed_url.query:
        retval += f"?{parsed_url.query}"
    if parsed_url.fragment:
        retval += f"#{parsed_url.fragment}"
    logging.debug("update_netloc: %s", retval)
    return retval


def rewrite_url(soup: BeautifulSoup) -> BeautifulSoup:
    """ if the base URL needs updating, we can rewrite it! takes in the original soup object
        and returns a new metadata one """
    metadata = get_metadata(soup)

    if not settings.rewrite_location:
        return metadata

    # we have to parse the metadata to grab the content because it's nested
    meta_soup = BeautifulSoup(metadata.text, features="xml")
    logging.debug("before rewrite:\n%s", meta_soup.contents)

    # updating the logout URL
    # update this: md:SingleLogoutService -> attr=Location
    slo = meta_soup.find("md:SingleLogoutService")
    if not slo:
        logging.debug("Couldn't find md:SingleLogoutService element")
    else:
        if "Location" not in slo.attrs:
            logging.debug("Couldn't find Location attribute in md:SingleLogoutService element")
        else:
            logging.debug("SLO Location: %s", slo.attrs['Location'])
            parsed_url = urllib.parse.urlparse(slo.attrs['Location'])
            logging.debug("parsed SLO_url=%s", parsed_url)
            slo.attrs["Location"] = update_netloc(parsed_url)
    # update this: md:AssertionConsumerService -> attr=Location
    acs = meta_soup.find("md:AssertionConsumerService")
    if not acs:
        logging.debug("Couldn't find md:AssertionConsumerService element")
    else:
        if "Location" not in acs.attrs:
            logging.debug("Couldn't find Location attribute in md:AssertionConsumerService element")
        else:
            logging.debug("ACS Location: %s", acs.attrs['Location'])
            parsed_url = urllib.parse.urlparse(acs.attrs['Location'])
            logging.debug("parsed ACS url=%s", parsed_url)
            acs.attrs["Location"] = update_netloc(parsed_url)


    logging.debug("after rewrite:\n%s", meta_soup.contents)
    return meta_soup

def fix_slo_index() -> None:
    """ this removes the 'index' attribute from the SLO tag """
    raise NotImplementedError

def parse_xml_error(content: bytes) -> str:
    """ parses an XML error to make it prettier """
    soup = BeautifulSoup(content)
    message = soup.find("msg", attrs={"type":"ERROR"})
    if not message:
        return content.decode("utf-8")
    return str(message.text)

@app.get("/")
async def root(
    #request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
) -> Response:
    """homepage"""
    if credentials is None:
        if settings.splunk_username is not None and settings.splunk_username is not None:
            credentials=HTTPBasicCredentials(
                username=settings.splunk_username,
                password=settings.splunk_password,
                )
            logging.debug(
                "Using config username/password: %s:%s",
                settings.splunk_username,
                str(settings.splunk_password)[:5],
                )
        else:
            raise HTTPException(401, "Please provide authentication")

    async with aiohttp.ClientSession() as session:
        try:
            response = await session.get(
                f"{settings.base_url}{URI_SP_METADATA}",
                auth=aiohttp.BasicAuth(credentials.username, credentials.password),
            )
            content = await response.content.read()
            response.raise_for_status()
        except aiohttp.client_exceptions.ClientResponseError as client_error:
            logging.error(
                "client error connecting to '%s': %s",
                client_error.request_info.url,
                client_error.message,
                )
            try:
                human_error = parse_xml_error(content) #pylint: disable=used-before-assignment
            except NameError: # we didn't get to the content-reading bit
                human_error = client_error.message

            # pylint: disable=raise-missing-from
            raise HTTPException(
                client_error.status,
                human_error,
            )


    soup = BeautifulSoup(content, features="xml")

    metadata = get_metadata(soup)
    if not metadata:
        return Response(
            json.dumps({
                "message": "Couldn't find spMetadata field",
                "response_content" : content.decode("utf-8")}),
            headers={"content_type": "application/json"},
            status_code=400,
        )

    if settings.rewrite_location:
        metadata = rewrite_url(soup)

    return Response(metadata.contents[0])
