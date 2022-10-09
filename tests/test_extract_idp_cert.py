""" testing the idp cert thing """


from splunk_saml_shim import get_cert_from_xml

TEST_XML = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://saml.yaleman.org">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>SUPER EXCITING SIGNING CERTIFICATE GOES HERE</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>SUPER EXCITING ENCRYPTION CERTIFICATE GOES HERE</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://saml.example.com/saml2/idp/SingleLogoutService.php"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://saml.example.com/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor>
  <md:ContactPerson contactType="technical">
    <md:GivenName>yaleman</md:GivenName>
    <md:EmailAddress>mailto:saml@terminaloutcomes.com</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>"""

def test_cert() -> None:
    """ tests pulling the cert out of the XML """

    assert get_cert_from_xml(TEST_XML.encode("utf-8")) == "SUPER EXCITING ENCRYPTION CERTIFICATE GOES HERE"
