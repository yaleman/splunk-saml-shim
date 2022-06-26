# splunk-saml-shim

A little shim to allow automagic pulling of the SAML metadata from your Splunk server without having to:

- have the API open
- have your authentication server have to be able to parse the XML response from Splunk
- provide a pretty powerful user to your authentication server (though, that's an option too, see Usage)


## Installation

Install this library using `pip`:

    $ python -m pip install git+https://github.com/yaleman/splunk-saml-shim


## Building the container

```shell
docker build -t ghcr.io/yaleman/splunk-saml-shim:latest .
```

## Usage

Copy the example.env to .env and set your settings.

Run it in a container:

```shell
docker run --rm -it \
    -v $(pwd)/.env:/data/.env \
    -p 8000:8000 \
    ghcr.io/yaleman/splunk-saml-shim:latest
```

### Authentication

There's two ways for the request authentication to happen:

- Send a valid-to-your-Splunk-instance username and password in basic authentication
- Configure the username and password in the configuration file

If you send basic auth it'll just use that. If you don't send auth with the request, and it is set in the configuration file, it'll use that. If that doesn't work it'll bail on you. :)
