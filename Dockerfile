FROM python:3.8
ENV TZ="Europe/Amsterdam"

ADD requirements*.txt /
RUN pip install -r /requirements.txt

ADD *.py /
ADD instance /instance

ADD application /application
ADD .pylintrc /

ADD test /test

## Run pylint and tests
#RUN pip install pylint && pylint entrypoint.py application/ && pip uninstall -y pylint
RUN pip install -r /requirements-test.txt && python -m pytest test/ && pip uninstall -y -r /requirements-test.txt

ENV PORT "5000"

EXPOSE 5000

ENV IRMA_CLIENT_SERVER_URL "https://irma-auth.sns.gidsopenstandaarden.org/"
ENV FLASK_ENV="production"

ENTRYPOINT [ "python", "entrypoint.py"]
