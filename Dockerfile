# Base Image
FROM python:3.8-alpine

RUN mkdir /app
WORKDIR /app

ADD . /app/

ENV PYTHONUNBUFFERED 1
ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive 

RUN pip3 install -r requirements.txt 

EXPOSE 8888
WORKDIR /app/unlock-git
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8888"]
