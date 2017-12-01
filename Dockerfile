FROM python:2.7-alpine

RUN apk update && apk add --no-cache git chromium-chromedriver && pip install splinter

RUN git clone -b v2 https://github.com/lightos/credmap.git
WORKDIR credmap
ENTRYPOINT ["python", "credmap.py"]