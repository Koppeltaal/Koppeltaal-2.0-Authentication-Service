FROM python:3.9
ENV TZ="Europe/Amsterdam"

RUN pip install poetry

ADD poetry.lock /
ADD pyproject.toml /
RUN poetry install

ADD *.py /
ADD instance /instance

ADD application /application
ADD .pylintrc /

ADD test /test

## Run pylint and tests
#RUN pip install pylint && pylint entrypoint.py application/ && pip uninstall -y pylint
RUN poetry install --with test && poetry run python -m pytest test/ && poetry install --without test

ENV PORT "5000"

EXPOSE 5000

ENV IRMA_CLIENT_SERVER_URL "https://irma-auth.sns.gidsopenstandaarden.org/"
ENV FLASK_ENV="production"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["poetry", "run", "python", "entrypoint.py"]
