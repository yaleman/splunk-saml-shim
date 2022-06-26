""" test parsing things """

import urllib.parse

def test_urlparse_assumptions() -> None:
    """ tests some assumptions about parsing """

    # this is a broken URL but it's me testing things
    weird_fragment = urllib.parse.urlparse("https://example.com:1234/testpath#epicfragment?query=value")
    print(weird_fragment)
    assert weird_fragment.fragment == "epicfragment?query=value"
    assert weird_fragment.query == ""


    with_query_and_url = urllib.parse.urlparse("https://example.com:1234/testpath?query=value&another=test#epicfragment")
    print(with_query_and_url)
    assert with_query_and_url.fragment == "epicfragment"
    assert with_query_and_url.query == "query=value&another=test"
