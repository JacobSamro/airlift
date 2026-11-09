#!/usr/bin/env python3
"""Regenerate the XML-DSig / SAML test vectors with an INDEPENDENT
implementation: libxml2 exclusive c14n (lxml) + openssl RSA-SHA256.

  cd src/sso/testdata
  openssl req -x509 -newkey rsa:2048 -nodes -keyout idp.key -out idp.crt -days 3650 -subj /CN=test-idp
  openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 3650 -subj /CN=other
  python3 gen.py .   # needs lxml

The private keys are throwaway and not committed.
"""
import base64, hashlib, json, subprocess, sys
from lxml import etree

OUT = sys.argv[1]
DS = "http://www.w3.org/2000/09/xmldsig#"

def c14n(node, prefixes=None):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False,
                          inclusive_ns_prefixes=prefixes)

# ---- canonicalization vectors (libxml2 is the oracle) ----
cases = []
docs = [
  ('<r xmlns="urn:d" xmlns:a="urn:a" xmlns:unused="urn:u"><a:x a:k="1" b="2"><y>t&amp;&lt;&gt;"\'</y></a:x><z xmlns=""><w/></z></r>', [], ["r", "x", "z"]),
  ('<p:root xmlns:p="urn:p" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><p:v xsi:type="xs:string">a\tb</p:v><p:w attr="x&#9;y&#10;z"/></p:root>', ["xs"], ["root", "v", "w"]),
  ('<a xmlns="urn:a"><b xmlns="urn:b"><c xmlns="urn:a">x<![CDATA[<y>]]><?pi data?></c></b><!-- c --></a>', ["#default"], ["a", "b", "c"]),
  ('<doc><e  z="2"   a="1" xml:lang="en">  ü — ✓ \n</e></doc>', [], ["doc", "e"]),
]
for i, (xml, prefixes, locals_) in enumerate(docs):
    root = etree.fromstring(xml.encode())
    for local in locals_:
        node = root if etree.QName(root).localname == local else root.xpath(f"//*[local-name()='{local}']")[0]
        for pl in ([], prefixes):
            cases.append({"xml": xml, "target": local, "inclusive": pl,
                          "expected": c14n(node, [p for p in pl if p != "#default"] or None).decode()
                          if "#default" not in pl else None})
# lxml can't express "#default" in its API; drop those (covered in Rust tests)
cases = [c for c in cases if c["expected"] is not None]
json.dump(cases, open(f"{OUT}/c14n_cases.json", "w"), indent=1, ensure_ascii=False)

# ---- signed SAML responses ----
def sign(elem, signed_target, key, prefixes):
    """Insert an enveloped signature into `elem` (as a direct child, after
    Issuer) covering `elem`; digest/sign via libxml2 exc-c14n + openssl."""
    eid = elem.get("ID")
    digest = base64.b64encode(hashlib.sha256(c14n(elem, prefixes)).digest()).decode()
    pl = f'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="{" ".join(prefixes)}"/>' if prefixes else ""
    sig = etree.fromstring(f'''<ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{eid}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{pl}</ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>bogus-ignored</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>''')
    issuer = elem[0]
    elem.insert(list(elem).index(issuer) + 1, sig)
    si = sig.find(f"{{{DS}}}SignedInfo")
    signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=c14n(si), capture_output=True, check=True).stdout
    sig.find(f"{{{DS}}}SignatureValue").text = base64.b64encode(signed).decode()

RESPONSE = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_resp1" InResponseTo="_req42" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://air.example/api/v1/auth/sso/p1/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example/</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_assert1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml2:Issuer>https://idp.example/</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">jane.doe@corp.example</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="_req42" NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://air.example/api/v1/auth/sso/p1/saml/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml2:AudienceRestriction><saml2:Audience>https://air.example/api/v1/auth/sso/p1/saml/metadata</saml2:Audience></saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="displayName"><saml2:AttributeValue xsi:type="xs:string">Jane Dö &amp; Co</saml2:AttributeValue></saml2:Attribute>
      <saml2:Attribute Name="email"><saml2:AttributeValue xsi:type="xs:string">jane.doe@corp.example</saml2:AttributeValue></saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</samlp:Response>'''

doc = etree.fromstring(RESPONSE.encode())
assertion = doc.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
sign(assertion, assertion, "idp.key", ["xs"])
open(f"{OUT}/saml_assertion_signed.xml", "wb").write(etree.tostring(doc))

doc = etree.fromstring(RESPONSE.encode())
sign(doc, doc, "idp.key", ["xs"])
open(f"{OUT}/saml_response_signed.xml", "wb").write(etree.tostring(doc))
print(len(cases), "c14n cases")
