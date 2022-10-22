""" utils for things """
from typing import Optional

import warnings #pylint: disable=wrong-import-order
warnings.filterwarnings("ignore", "defusedxml.lxml is no longer supported and will be removed in a future release.", DeprecationWarning)
#pylint: disable=wrong-import-position
from defusedxml.lxml import _etree as etree #type: ignore

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
