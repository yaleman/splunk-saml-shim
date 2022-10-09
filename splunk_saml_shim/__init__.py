""" A shim that sits between Splunk and you, to make pulling the SAML metadata easier """

# pylint: disable=too-few-public-methods

import logging
import json
from typing import List, Optional
import urllib.parse

import aiohttp
import aiohttp.client_exceptions
from bs4 import BeautifulSoup # type: ignore[import]
import bs4.element # type: ignore[import]
from fastapi import Depends, FastAPI, Response, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseSettings

from lxml import etree # type: ignore[import]


# ref: https://docs.splunk.com/Documentation/Splunk/9.0.0/RESTREF/RESTaccess#admin.2FSAML-sp-metadata
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

    idp_metadata_url: Optional[str] = None

    log_level: str = "INFO"
    # if this is going to be hosted under a sub-path set it here
    root_path: str = "/"

    class Config:
        """config of the config"""

        env_file = ".env"
        env_file_encoding = "utf-8"

    @property
    def base_url(self) -> str:
        """returns the URL"""
        return f"{self.splunk_scheme}://{self.splunk_hostname}:{self.splunk_port}"


settings = AppConfig()
app = FastAPI(root_path=settings.root_path)

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
    if settings.dict().get("rewrite_scheme") is not None:
        scheme = settings.dict().get("rewrite_scheme")
    else:
        scheme = parsed_url.scheme
    if settings.dict().get("rewrite_host") is not None:
        hostname = settings.dict().get("rewrite_host")
    else:
        hostname = parsed_url.netloc

    retval = f"{scheme}://{hostname}{parsed_url.path}"
    if parsed_url.params:
        retval += f";{parsed_url.params}"
    if parsed_url.query:
        retval += f"?{parsed_url.query}"
    if parsed_url.fragment:
        retval += f"#{parsed_url.fragment}"
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

def get_cert_from_xml(xmldata: bytes) -> Optional[str]:
    """ pulls the cert from the XML"""

    idpspasstree = etree.fromstring(xmldata)
    # idpspassroot = idpspasstree.getroot()
    # entityId = idpspassroot.get('entityID')
    # self.idpMetaDetails._entityId = entityId
    namespace_xmlns = 'urn:oasis:names:tc:SAML:2.0:metadata'
    xpath_selector = "//x:KeyDescriptor[@use='signing']/*/*/*"
    # signing_keyDescriptors = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
    xpath_selector = "//x:KeyDescriptor[@use='encryption']/*/*/*"
    encryption_key_descriptors = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
    # for signingKeyInfo in signing_keyDescriptors:
    #     signingcert = signingKeyInfo.text.strip()
    #     # self.idpMetaDetails._signingCert = signingcert
    #     break
    content = None

    for encryption_key_info in encryption_key_descriptors:
        encryptcert = encryption_key_info.text.strip()
        content = encryptcert
        # self.idpMetaDetails._encryptionCert = encryptcert
        break
    # xpath_selector = "//x:ArtifactResolutionService"
    # artifactResolution = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
    # for artifacts in artifactResolution:
    #     if artifacts.attrib.get('Binding') == 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP' and artifacts.attrib.get(
    #             'index') == '0' and artifacts.attrib.get('isDefault') == 'true':
    #         httploc = artifacts.attrib.get('Location')
    #         self.idpMetaDetails._location = httploc
    #         break
    # return self.idpMetaDetails
    # message = soup.find("md:EmailAddress", recursive=True) #:X509Certificate
    # print(f"{message=}")

    # if message:
        # content = message

    return content

@app.get("/extract_idp_cert")
async def extract_idp_cert() -> Response:
    """ if you've set an IDP metadata url then you can pull the signing cert out of it """
    if settings.idp_metadata_url is None:
        return Response(status_code=404,content="Wot")
    async with aiohttp.ClientSession() as session:
        async with session.get(settings.idp_metadata_url) as request:
            status = request.status
            print(f"Status: {status}")
            content = await request.content.read()

            result = get_cert_from_xml(content)

            file_data = []
            if result is not None:
                file_data.append("-----BEGIN CERTIFICATE-----")
                for line in split_string(result, 64):
                    file_data.append(line)
                file_data.append("-----END CERTIFICATE-----")
    return Response(status_code=status, content="\n".join(file_data))


def split_string(string: str, num: int) -> List[str]:
    """ splits a string into a set of num-sized chunks. """
    return [string[i:i+num] for i in range(0, len(string), num)]

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
