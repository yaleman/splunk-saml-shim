FROM python:3.10-slim
# FROM python:3.10-alpine

########################################
# add a user so we're not running as root
########################################
RUN useradd pythonuser

RUN python -m pip install --no-cache --upgrade --quiet pip poetry

# RUN apt-get update
# RUN apt-get install -y git
RUN apt-get clean

RUN mkdir -p build/splunk_saml_shim

WORKDIR /build
ADD splunk_saml_shim /build/splunk_saml_shim
COPY poetry.lock .
COPY README.md .
COPY pyproject.toml .

RUN mkdir -p /home/pythonuser/
RUN chown pythonuser /home/pythonuser -R
RUN chown pythonuser /build -R
RUN mkdir -p /data/

WORKDIR /data
USER pythonuser

RUN python -m pip install --no-cache /build/
USER root
RUN rm -rf /build/
USER pythonuser
WORKDIR /data

CMD ["python", "-m", "splunk_saml_shim" ]
